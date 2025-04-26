#include "server.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/time.h>

#include "sqlite3.h"

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#define PORT 4400
#define MAX_CLIENTS 50
#define THREAD_POOL_SIZE 5
#define MAX_TASKS 100
#define SERVER_CERT "./certs/server.crt"
#define SERVER_KEY "./certs/server.key"
#define MAX_BROADCASTS 100
#define BROADCAST_LIFETIME 1800
#define IDLE_TIMEOUT 3600

Client clients[MAX_CLIENTS];
struct pollfd fds[MAX_CLIENTS + 1];
int client_count = 0;
volatile sig_atomic_t shutdown_requested = 0;

Task task_queue[MAX_TASKS];
int task_front = 0, task_rear = 0;

int udp_broadcast;
Broadcast broadcasts[MAX_BROADCASTS];
int broadcast_count = 0;

pthread_mutex_t queue_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t queue_cond = PTHREAD_COND_INITIALIZER;
pthread_mutex_t client_mutex = PTHREAD_MUTEX_INITIALIZER;

sqlite3 *db;

int main() {
	signal(SIGINT, handle_sigint);
	signal(SIGTERM, handle_sigint);

	SSL_library_init();
	SSL_load_error_strings();
	OpenSSL_add_ssl_algorithms();
	SSL_CTX *ssl_ctx = create_ssl_context();
	SSL_CTX_set_min_proto_version(ssl_ctx, TLS1_2_VERSION);
	SSL_CTX_set_max_proto_version(ssl_ctx, TLS1_3_VERSION);

	create_open_db();

	const int server_fd = socket(AF_INET, SOCK_STREAM, 0);
	if (udp_broadcast < 0) {
		perror("TCP socket creation failed");
		exit(EXIT_FAILURE);
	}
	udp_broadcast = socket(AF_INET, SOCK_DGRAM, 0);
	if (udp_broadcast < 0) {
		perror("UDP socket creation failed");
		exit(EXIT_FAILURE);
	}
	struct sockaddr_in addr = {.sin_family = AF_INET, .sin_port = htons(PORT), .sin_addr.s_addr = INADDR_ANY};
	if (bind(server_fd, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		fprintf(stderr, "[!] TCP Socket binding failed, is port already in use?\n");
		SSL_CTX_free(ssl_ctx);
		close(server_fd);
		close(udp_broadcast);
		sqlite3_close(db);
		return EXIT_FAILURE;
	}
	if (bind(udp_broadcast, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		fprintf(stderr, "[!] UDP Socket binding failed, is port already in use?\n");
		SSL_CTX_free(ssl_ctx);
		close(udp_broadcast);
		close(server_fd);
		sqlite3_close(db);
		return EXIT_FAILURE;
	}


	listen(server_fd, 10);
	make_non_blocking(server_fd);

	fds[0].fd = server_fd;
	fds[0].events = POLLIN;

	pthread_t pool[THREAD_POOL_SIZE];
	for (int i = 0; i < THREAD_POOL_SIZE; ++i) {
		pthread_create(&pool[i], NULL, worker_thread, NULL);
	}

	printf("[+] Secure server running on port %d\n", PORT);

	while (!shutdown_requested) {
		int ready = poll(fds, client_count + 1, 1000);
		if (ready < 0) continue;

		if (accept_incoming_connections(ssl_ctx, server_fd)) continue;

		queue_client_task();
		kick_idle_clients();
	}

	for (int i = 0; i < THREAD_POOL_SIZE; ++i) {
		pthread_join(pool[i], NULL);
	}

	printf("[*] Shutting down. Disconnecting all clients...\n");
	for (int i = client_count - 1; i >= 0; i--) {
		SSL_write(clients[i].ssl, "eServer shutting down. Goodbye!\n", 33);
		remove_client(i);
	}

	SSL_CTX_free(ssl_ctx);
	close(server_fd);
	close(udp_broadcast);
	sqlite3_close(db);
	return 0;
}


void display_clients(const Client *client) {
	char list[4096] = "d[";
	bool first = true;

	pthread_mutex_lock(&client_mutex);
	for (int i = 0; i < client_count; i++) {
		if (clients[i].active && clients[i].username[0] != '\0' && &clients[i] != client) {
			if (!first) {
				strcat(list, ",");
			}
			char entry[128];
			snprintf(entry, sizeof(entry),
				"{\"username\":\"%s\",\"ip\":\"%s\"}",
				clients[i].username,
				inet_ntoa(clients[i].address.sin_addr)
			);
			strcat(list, entry);
			first = false;
		}
	}
	pthread_mutex_unlock(&client_mutex);

	strcat(list, "]\n");
	SSL_write(client->ssl, list, (int)strlen(list));
}


void update_activity(const char *username) {
	sqlite3_stmt *stmt;
	const char *sql = "UPDATE users SET last_activity = CURRENT_TIMESTAMP WHERE username = ?;";

	if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) {
		fprintf(stderr, "[!] Failed to prepare statement: %s\n", sqlite3_errmsg(db));
		return;
	}

	if (sqlite3_bind_text(stmt, 1, username, -1, SQLITE_STATIC) != SQLITE_OK) {
		fprintf(stderr, "[!] Failed to bind username: %s\n", sqlite3_errmsg(db));
		sqlite3_finalize(stmt);
		return;
	}

	if (sqlite3_step(stmt) != SQLITE_DONE) {
		fprintf(stderr, "[!] Failed to execute statement: %s\n", sqlite3_errmsg(db));
	} else {
		//printf("Updated last_activity for user '%s'.\n", username);
	}

	sqlite3_finalize(stmt);
}

void kick_idle_clients() {
	sqlite3_stmt *stmt;
	const char *sql = "SELECT username FROM users "
					  "WHERE active = 1 "
					  "AND last_activity IS NOT NULL "
					  "AND (strftime('%s','now') - strftime('%s', last_activity)) > ?;";

	if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) {
		fprintf(stderr, "[!] Failed to prepare idle check query: %s\n", sqlite3_errmsg(db));
		return;
	}

	sqlite3_bind_int(stmt, 1, IDLE_TIMEOUT);

	pthread_mutex_lock(&client_mutex);

	while (sqlite3_step(stmt) == SQLITE_ROW) {
		const char *username = (const char *)sqlite3_column_text(stmt, 0);

		for (int i = 0; i < client_count; i++) {
			if (clients[i].active && strcmp(clients[i].username, username) == 0) {
				printf("[!] Disconnecting idle client %s (timeout).\n", username);
				disconnect_client(&clients[i], "eDisconnected due to inactivity.\n");
				break; // since client list shifts after remove_client()
			}
		}
	}

	pthread_mutex_unlock(&client_mutex);

	sqlite3_finalize(stmt);
}



void db_client_inactive(const char *username) {
	sqlite3_stmt *stmt;
	const char *sql = "UPDATE users SET active = 0 WHERE username = ?;";

	if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) {
		fprintf(stderr, "[!] Failed to prepare statement to mark user inactive: %s\n", sqlite3_errmsg(db));
		return;
	}

	sqlite3_bind_text(stmt, 1, username, -1, SQLITE_STATIC);

	if (sqlite3_step(stmt) != SQLITE_DONE) {
		fprintf(stderr, "[!] Failed to update user status: %s\n", sqlite3_errmsg(db));
	} else {
		//printf("[*] Marked user '%s' as inactive in the database.\n", username);
	}

	sqlite3_finalize(stmt);
}


void db_client_active(const char *username) {
	sqlite3_stmt *stmt;
	const char *sql = "UPDATE users SET active = 1 WHERE username = ?;";

	if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) {
		fprintf(stderr, "[!] Failed to prepare statement to mark user inactive: %s\n", sqlite3_errmsg(db));
		return;
	}

	sqlite3_bind_text(stmt, 1, username, -1, SQLITE_STATIC);

	if (sqlite3_step(stmt) != SQLITE_DONE) {
		fprintf(stderr, "[!] Failed to update user status: %s\n", sqlite3_errmsg(db));
	} else {
		//printf("[*] Marked user '%s' as inactive in the database.\n", username);
	}

	sqlite3_finalize(stmt);
}


void cleanup_broadcasts() {
	const time_t now = time(NULL);
	int new_count = 0;

	for (int i = 0; i < broadcast_count; ++i) {
		if (now - broadcasts[i].timestamp <= BROADCAST_LIFETIME) {
			broadcasts[new_count++] = broadcasts[i];
		}
	}
	broadcast_count = new_count;
}


void store_broadcast(const char *sender, const char *msg_body) {
	const time_t now = time(NULL);
	const struct tm *local = localtime(&now);
	char time_str[16];
	strftime(time_str, sizeof(time_str), "%-m/%-d %H:%M", local);
	char full_msg[256];
	snprintf(full_msg, sizeof(full_msg), "b[%s %s] %s\n", sender, time_str, msg_body);

	if (broadcast_count < MAX_BROADCASTS) {
		snprintf(broadcasts[broadcast_count].message, sizeof(broadcasts[0].message), "%s", full_msg);
		broadcasts[broadcast_count].timestamp = now;
		broadcast_count++;
	}

	// Cleanup
	cleanup_broadcasts();
}


void send_broadcasts(Client *target, bool send_to_all, const char *single_message) {
	cleanup_broadcasts();

	pthread_mutex_lock(&client_mutex);
	time_t now = time(NULL);

	if (send_to_all) {
		for (int i = 0; i < client_count; ++i) {
			if (clients[i].active && clients[i].username[0] != 0)  {
				struct sockaddr_in udp_addr = clients[i].address;
				udp_addr.sin_port = htons(PORT);
				sendto(udp_broadcast, single_message, strlen(single_message), 0,
					   (struct sockaddr *)&udp_addr, sizeof(udp_addr));
			}
		}
	} else {
		if (!target || !target->active) {
			pthread_mutex_unlock(&client_mutex);
			return;
		}

		for (int i = 0; i < broadcast_count; ++i) {
			if (now - broadcasts[i].timestamp <= BROADCAST_LIFETIME) {
				struct sockaddr_in udp_addr = target->address;
				udp_addr.sin_port = htons(PORT);
				sendto(udp_broadcast, broadcasts[i].message, strlen(broadcasts[i].message), 0,
					   (struct sockaddr *)&udp_addr, sizeof(udp_addr));
			}
		}
	}

	pthread_mutex_unlock(&client_mutex);
}


void broadcast_message(Client *sender, const char *msg_body) {
	printf("[+] User %s broadcasting: %s", sender->username, msg_body);

	store_broadcast(sender->username, msg_body);
	send_broadcasts(NULL, true, broadcasts[broadcast_count - 1].message);
}

//true if exists, false if not.
int check_username(const char *username) {
	sqlite3_stmt *stmt;
	const char *sql = "SELECT 1 FROM users WHERE username = ? LIMIT 1;";

	if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) {
		fprintf(stderr, "Failed to prepare statement: %s\n", sqlite3_errmsg(db));
		return -1; //something broke
	}

	sqlite3_bind_text(stmt, 1, username, -1, SQLITE_STATIC);

	int exists = 0;
	if (sqlite3_step(stmt) == SQLITE_ROW) {
		exists = 1;  // username exists
	}

	sqlite3_finalize(stmt);
	return exists;
}

int hash_and_salt(char *password, const char *salt) {
	int iterations = 100000;
	int keylen = 32;
	char hash[32];

	if (PKCS5_PBKDF2_HMAC(password, strlen(password), (const unsigned char*) salt, 16,
						  iterations, EVP_sha256(), keylen, (unsigned char*)hash) != 1) {
		fprintf(stderr, "Error during PBKDF2\n");
		return 1;
						  }

	/*printf("Derived key: ");
	for (int i = 0; i < keylen; i++)
		printf("%02x", hash[i]);
	printf("\n");*/
	memcpy(password, hash, 32);

	return 0;
}

bool check_password(const char *username,const char *password) {
	sqlite3_stmt *stmt;
	const char *sql = "SELECT password_hash, password_salt FROM users WHERE username = ? LIMIT 1;";

	if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) {
		fprintf(stderr, "Failed to prepare statement: %s\n", sqlite3_errmsg(db));
		return -1; //something broke
	}

	sqlite3_bind_text(stmt, 1, username, -1, SQLITE_STATIC);

	if (sqlite3_step(stmt) == SQLITE_ROW) {
		const void *password_hash = sqlite3_column_blob(stmt, 0);
		const void *salt = sqlite3_column_blob(stmt, 1);
		hash_and_salt((char*) password, salt);

		if (memcmp(password_hash, password, 32) == 0) {
			sqlite3_finalize(stmt);
			return true;
		}
	}

	sqlite3_finalize(stmt);
	return false;
}


int create_user(const char *username, char *password) {
	sqlite3_stmt *stmt;
	const char *sql = "INSERT INTO users (username, password_hash, password_salt, last_activity) VALUES (?, ?, ?, CURRENT_TIMESTAMP);";

	if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) {
		fprintf(stderr, "Prepare failed: %s\n", sqlite3_errmsg(db));
		return -1;
	}

	sqlite3_bind_text(stmt, 1, username, -1, SQLITE_STATIC);

	const char salt[16];
	RAND_bytes((unsigned char *)salt, 16);
	hash_and_salt(password, salt);

	sqlite3_bind_blob(stmt, 2, password, 32, SQLITE_STATIC);
	sqlite3_bind_blob(stmt, 3, salt, 16, SQLITE_STATIC);

	int result = 0;
	if (sqlite3_step(stmt) != SQLITE_DONE) {
		fprintf(stderr, "Insert failed: %s\n", sqlite3_errmsg(db));
		result = -1;
	}

	sqlite3_finalize(stmt);
	return result;
}

void disconnect_client(Client *client, const char *reason) {
	if (!client) return;

	pthread_mutex_lock(&client_mutex);

	if (!client->active) {
		pthread_mutex_unlock(&client_mutex);
		return;
	}

	if (reason) SSL_write(client->ssl, reason, (int)strlen(reason));

	int index = -1;
	for (int i = 0; i < client_count; ++i) {
		if (&clients[i] == client) {
			index = i;
			break;
		}
	}

	pthread_mutex_unlock(&client_mutex);

	if (index != -1) {
		remove_client(index);
	}
}


bool login_or_signup(Client *client) {
	int msglen = (int)strlen(client->buffer + 1);

	if (client->buffer[msglen] == '\n') {
		client->buffer[msglen] = '\0';
		msglen = msglen - 1;
	}

	//signup
	if (client->buffer[0] == 's') {
		if (client->state == INITIAL) {
			SSL_write(client->ssl, "sEnter new username:\n", 22);
			client->state = CREATE_USERNAME;
			return false;
		}
		if (client->state == CREATE_USERNAME) {


			if (msglen > 20) {
				SSL_write(client->ssl, "sUsername too long! Try again.\nEnter new username:\n", 52);
				return false;
			}

			if (check_username(client->buffer + 1) != 0) {
				SSL_write(client->ssl, "sUsername exists! Try again.\nEnter new username:\n", 49);
				return false;
			}

			strcpy(client->username, client->buffer + 1);
			client->state = CREATE_PASSWORD;
			SSL_write(client->ssl, "sEnter new password:\n", 22);
			return false;
		}
		if (client->state == CREATE_PASSWORD) {
			if (msglen > 30) {
				SSL_write(client->ssl, "sPassword too long! Try again.\nEnter new password:\n", 52);
				return false;
			}
			memcpy(client->password, client->buffer + 1, 32);
			client->state = CREATE_CONFIRM_PASSWORD;
			SSL_write(client->ssl, "sConfirm password:\n", 20);
			return false;
		}
		if (client->state == CREATE_CONFIRM_PASSWORD) {
			if (msglen > 30) {
				SSL_write(client->ssl, "sPasswords do not match! Try again.\nEnter new password:\n", 57);
				memset(client->password, 0, sizeof(client->password));
				client->state = CREATE_PASSWORD;
				return false;
			}
			if (strcmp(client->password, client->buffer + 1) == 0) {
				create_user(client->username, client->password);
				memset(client->password, 0, sizeof(client->password)); //clear for security
				client->state = AUTHENTICATED;
				return true;
			}
			SSL_write(client->ssl, "sPasswords do not match! Try again.\nEnter new password:\n", 57);
			memset(client->password, 0, sizeof(client->password));
			client->state = CREATE_PASSWORD;
			return false;
		}
	}

	//login
	if (client->buffer[0] == 'l') {
		if (client->state == INITIAL) {
			SSL_write(client->ssl, "lEnter username:\n", 18);
			client->state = LOGIN_USERNAME;
			return false;
		}
		if (client->state == LOGIN_USERNAME) {
			if (msglen > 20) {
				SSL_write(client->ssl, "lUsername too long! Try again.\nEnter username:\n", 48);
				return false;
			}

			strcpy(client->username, client->buffer + 1);
			SSL_write(client->ssl, "lEnter password:\n", 18);
			client->state = LOGIN_PASSWORD;
			return false;
		}
		if (client->state == LOGIN_PASSWORD) {
			if (msglen > 32) {
				SSL_write(client->ssl, "lPassword too long! Try again.\nEnter username:\n", 48);
				client->state = LOGIN_USERNAME;
				client->login_attempts = client->login_attempts + 1;
				if (client->login_attempts == 3) {
					disconnect_client(client, "eToo many login attempts!\n");
				}
				return false;
			}

			memcpy(client->password, client->buffer + 1, 32);
			if (check_username(client->username) == false) {
				SSL_write(client->ssl, "lIncorrect credentials! Try again.\nEnter username:\n", 52);
				client->state = LOGIN_USERNAME;
				client->login_attempts = client->login_attempts + 1;
				if (client->login_attempts == 3) {
					disconnect_client(client, "eToo many login attempts!\n");
				}
				return false;
			}

			if (check_password(client->username, client->password)) {
				update_activity(client->username);
				db_client_active(client->username);
				return true;
			}
			SSL_write(client->ssl, "lIncorrect credentials! Try again.\nEnter username:\n", 52);
			client->state = LOGIN_USERNAME;
			client->login_attempts = client->login_attempts + 1;
			if (client->login_attempts == 3) {
				disconnect_client(client, "eToo many login attempts!\n");
				return false;
			}
		}
	}

	return false;
}

void *worker_thread() {
	while (!shutdown_requested) {
		pthread_mutex_lock(&queue_mutex);
		while (task_front == task_rear && !shutdown_requested) {
			pthread_cond_wait(&queue_cond, &queue_mutex);
		}

		if (shutdown_requested) {
			pthread_mutex_unlock(&queue_mutex);
			break;
		}

		Task task = task_queue[task_front];
		task_front = (task_front + 1) % MAX_TASKS;
		pthread_mutex_unlock(&queue_mutex);

		Client *client = task.client;
		if (!client->active) continue;

		if (client->username[0] != 0) update_activity(client->username);
		//printf("[Worker] Handling message: %s\n", task.message);

		if (client->state == INITIAL || client->state == CREATE_USERNAME || \
			client->state == CREATE_PASSWORD || client->state == CREATE_CONFIRM_PASSWORD || \
			client->state == LOGIN_USERNAME || client->state == LOGIN_PASSWORD) {
			if (login_or_signup(client)) {
				db_client_active(client->username);
				char buffer[33]; // 21(max username) + 11 (text below)
				snprintf(buffer, 33, "aWelcome, %s!\n", client->username);
				SSL_write(client->ssl, buffer, (int)strlen(buffer));
				printf("[+] Client %d logged in as %s.\n",client->fd,client->username);
				client->state = AUTHENTICATED;
				send_broadcasts(client,false,NULL);
			}
		} else if (client->state == AUTHENTICATED) {
			if (client->buffer[0] == 'b') {
				broadcast_message(client, client->buffer + 1);
				SSL_write(client->ssl, "aMessage broadcasted.\n", 23);
			} else if (client->buffer[0] == 'd') {
				display_clients(client);
			} else if (client->buffer[0] == 'c') {
				int len = strlen(client->buffer);
				if (len > 0 && client->buffer[len - 1] == '\n') {
					client->buffer[len - 1] = '\0';
				}
				struct in_addr target_addr;
				if (inet_pton(AF_INET,client->buffer + 1, &target_addr) <= 0) {
					pthread_mutex_unlock(&client_mutex);
					SSL_write(client->ssl, "aUser not available.\n", 22);
					break;
				}
				pthread_mutex_lock(&client_mutex);
				Client *target = NULL;
				for (int i = 0; i < client_count; i++) {
					if (clients[i].active && (clients[i].address.sin_addr.s_addr == target_addr.s_addr)) {
						target = &clients[i];
						break;
					}
				}

				if (client == target) {
					pthread_mutex_unlock(&client_mutex);
					SSL_write(client->ssl, "aUser not available.\n", 22);
					break;
				}

				if (target) {
					char buff[1024];
					client->state = IN_HANDOFF;
					target->state = D_HANDOFF;
					client->handoff = target;
					target->handoff = client;
					snprintf(buff, sizeof(buff),
				"hConnection request from %s, %s. Accept (y/n)?\n",
				client->username,
				inet_ntoa(client->address.sin_addr)
			);
					SSL_write(target->ssl, buff, (int)strlen(buff));
				} else {
					SSL_write(client->ssl, "aUser not available.\n", 22);
				}
				pthread_mutex_unlock(&client_mutex);
			}
		} else if (client->state == D_HANDOFF) {
			if (client->buffer[0] == 'h') {
				if (client->buffer[1] == 'y' || client->buffer[1] == 'Y') {
					// Accepted
					Client *partner = client->handoff;
					if (partner && partner->active) {
						char buf[128];
						snprintf(buf, sizeof(buf), "hConnect to %s:%d\n",
							inet_ntoa(client->address.sin_addr),
							ntohs(client->address.sin_port));
						SSL_write(partner->ssl, buf, (int)strlen(buf));

						snprintf(buf, sizeof(buf), "hConnect to %s:%d\n",
							inet_ntoa(partner->address.sin_addr),
							ntohs(partner->address.sin_port));
						SSL_write(client->ssl, buf, (int)strlen(buf));

						disconnect_client(partner, NULL);
						disconnect_client(client, NULL);
					}
				} else {
					// Declined
					Client *partner = client->handoff;
					if (partner && partner->active) {
						SSL_write(partner->ssl, "aConnection request declined.\n", 30);
						disconnect_client(partner, NULL);
					}
					client->state = AUTHENTICATED;
				}
			}
		}

	}

	printf("[Worker] Thread exiting.\n");
	return NULL;
}

void handle_sigint(const int sig) {
	if (sig == 15) {
		printf("\nCaught SIGTERM. Shutting down...\n");
	} else {
		printf("\nCaught SIGINT. Shutting down...\n");
	}
	shutdown_requested = 1;
	pthread_cond_broadcast(&queue_cond);
}

void create_open_db() {
	char *zErrMsg = NULL;
	if (sqlite3_open("server.db", &db)) {
		fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(db));
		sqlite3_close(db);
		exit(1);
	}
	if (sqlite3_exec(db, "CREATE TABLE IF NOT EXISTS users ( \
                      username TEXT PRIMARY KEY, \
                      password_hash BLOB NOT NULL, \
					  password_salt BLOB NOT NULL, \
                      last_activity TIMESTAMP, \
                      active BOOLEAN NOT NULL DEFAULT 1);",NULL,NULL, &zErrMsg
	    ) != SQLITE_OK) {
		fprintf(stderr, "Can't create database: %s\n", zErrMsg);
	}

	printf("Connected to database...\n");
}

int shutdown_ssl_gracefully(SSL *ssl, int fd, int timeout_ms) {
	struct timeval start, now;
	gettimeofday(&start, NULL);

	while (1) {
		int ret = SSL_shutdown(ssl);
		if (ret == 1) return 1;
		if (ret == 0) continue;

		int err = SSL_get_error(ssl, ret);
		if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
			gettimeofday(&now, NULL);
			long elapsed = (now.tv_sec - start.tv_sec) * 1000 +
			               (now.tv_usec - start.tv_usec) / 1000;
			if (elapsed > timeout_ms) {
				fprintf(stderr, "[!] SSL_shutdown timeout on fd %d\n", fd);
				return -1;
			}
			usleep(10000);
		} else {
			return -1;
		}
	}
}

void remove_client(int i) {
	pthread_mutex_lock(&client_mutex);
	if (i < 0 || i >= client_count || !clients[i].active) {
		pthread_mutex_unlock(&client_mutex);
		return;
	}
	Client *client = &clients[i];

	if (!client->active) {
		pthread_mutex_unlock(&client_mutex);
		return;
	}

	client->active = false;
	db_client_inactive(client->username);
	memset(client->username, 0, sizeof(client->username));

	if (client->ssl) {
		shutdown_ssl_gracefully(client->ssl, client->fd, 500);
		SSL_free(client->ssl);
		client->ssl = NULL;
	}

	if (client->fd != -1) {
		close(client->fd);
		client->fd = -1;
	}
	for (int j = i; j < client_count - 1; ++j) {
		clients[j] = clients[j + 1];
		fds[j + 1] = fds[j + 2];
	}

	client_count--;
	pthread_mutex_unlock(&client_mutex);
}

int make_non_blocking(int fd) {
	int flags = fcntl(fd, F_GETFL, 0);
	return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

SSL_CTX *create_ssl_context() {
	SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
	if (!ctx) {
		fprintf(stderr, "Failed to create SSL context\n");
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}

	if (SSL_CTX_use_certificate_file(ctx, SERVER_CERT, SSL_FILETYPE_PEM) <= 0) {
		fprintf(stderr, "Failed to load server certificate from %s\n", SERVER_CERT);
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}

	if (SSL_CTX_use_PrivateKey_file(ctx, SERVER_KEY, SSL_FILETYPE_PEM) <= 0) {
		fprintf(stderr, "Failed to load server key from %s\n", SERVER_KEY);
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}

	return ctx;
}

void enqueue_task(Task task) {
	pthread_mutex_lock(&queue_mutex);
	task_queue[task_rear] = task;
	task_rear = (task_rear + 1) % MAX_TASKS;
	pthread_cond_signal(&queue_cond);
	pthread_mutex_unlock(&queue_mutex);
}

void queue_client_task(void) {
	for (int i = 0; i < client_count; ++i) {

		int idx = i + 1;
		Client *client = &clients[i];

		if (fds[idx].revents & POLLIN) {
			int bytes = SSL_read(client->ssl, client->buffer, sizeof(client->buffer) - 1);

			if (bytes > 0) {
				client->buffer[bytes] = '\0';
				Task task = {client};
				strncpy(task.message, client->buffer, sizeof(task.message) - 1);
				enqueue_task(task);
			} else {
				int err = SSL_get_error(client->ssl, bytes);

				if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) continue;

				if (err == SSL_ERROR_ZERO_RETURN) {
					printf("[-] Client %d disconnected (clean SSL shutdown).\n", client->fd);
				} else {
					fprintf(stderr, "[!] SSL_read error on fd %d: code %d\n", client->fd, err);
					ERR_print_errors_fp(stderr);
				}

				remove_client(i);
				i--;
			}
		}
	}
}

bool accept_incoming_connections(SSL_CTX *ssl_ctx, int server_fd) {
	if (fds[0].revents & POLLIN) {
		struct sockaddr_in cli_addr;
		socklen_t cli_len = sizeof(cli_addr);
		const int client_fd = accept(server_fd, (struct sockaddr*)&cli_addr, &cli_len);
		if (client_fd >= 0) {
			if (client_count >= MAX_CLIENTS) {
				fprintf(stderr, "[!] Max clients reached. Rejecting connection (fd: %d).\n", client_fd);
				close(client_fd); // Reject immediately
				return true;
			}
			SSL *ssl = SSL_new(ssl_ctx);
			SSL_set_fd(ssl, client_fd);
			printf("[+] New client connected (fd: %d, %d/%d). Starting SSL handshake...\n", client_fd, client_count+1, MAX_CLIENTS);

			if (SSL_accept(ssl) <= 0) {
				fprintf(stderr, "[!] SSL_accept failed for fd %d:\n", client_fd);
				ERR_print_errors_fp(stderr);
				SSL_free(ssl);
				close(client_fd);
				return true;
			}

			printf("[+] SSL handshake complete (fd: %d)\n", client_fd);
			make_non_blocking(client_fd);

			if (SSL_write(ssl, "iWelcome to the server!\nLogin or signup?\n", 42) <= 0) {
				fprintf(stderr, "[!] SSL_write failed after handshake for fd %d:\n", client_fd);
				ERR_print_errors_fp(stderr);
				SSL_shutdown(ssl);
				SSL_free(ssl);
				close(client_fd);
				return true;
			} else {
				printf("[+] Prompt sent to client %d\n", client_fd);
			}

			clients[client_count] = (Client){
				.fd = client_fd,
				.ssl = ssl,
				.state = INITIAL,
				.buffer = {0},
				.buffer_len = 0,
				.username = {0},
				.password = {0},
				.address = cli_addr,
				.active = true,
				.login_attempts = 0
			};
			fds[client_count + 1].fd = client_fd;
			fds[client_count + 1].events = POLLIN;
			client_count++;
		}
	}
	return false;
}
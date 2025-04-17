#include "server.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
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

Client clients[MAX_CLIENTS];
struct pollfd fds[MAX_CLIENTS + 1];
int client_count = 0;
volatile sig_atomic_t shutdown_requested = 0;

Task task_queue[MAX_TASKS];
int task_front = 0, task_rear = 0;

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

	createopen_db();

	int server_fd = socket(AF_INET, SOCK_STREAM, 0);
	struct sockaddr_in addr = {.sin_family = AF_INET, .sin_port = htons(PORT), .sin_addr.s_addr = INADDR_ANY};
	if (bind(server_fd, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		fprintf(stderr, "[!] Socket binding failed, is port already in use?\n");
		SSL_CTX_free(ssl_ctx);
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
	}

	for (int i = 0; i < THREAD_POOL_SIZE; ++i) {
		pthread_join(pool[i], NULL);
	}

	printf("[*] Shutting down. Disconnecting all clients...\n");
	for (int i = client_count - 1; i >= 0; i--) {
		SSL_write(clients[i].ssl, "Server shutting down. Goodbye!\n", 33);
		remove_client(i);
	}

	SSL_CTX_free(ssl_ctx);
	close(server_fd);
	sqlite3_close(db);
	return 0;
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
					disconnect_client(client, "Too many login attempts!\n");
				}
				return false;
			}

			memcpy(client->password, client->buffer + 1, 32);
			if (check_username(client->username) == false) {
				SSL_write(client->ssl, "lIncorrect credentials! Try again.\nEnter username:\n", 52);
				client->state = LOGIN_USERNAME;
				client->login_attempts = client->login_attempts + 1;
				if (client->login_attempts == 3) {
					disconnect_client(client, "Too many login attempts!\n");
				}
				return false;
			}

			if (check_password(client->username, client->password)) {
				return true;
			}
			SSL_write(client->ssl, "lIncorrect credentials! Try again.\nEnter username:\n", 52);
			client->state = LOGIN_USERNAME;
			client->login_attempts = client->login_attempts + 1;
			if (client->login_attempts == 3) {
				disconnect_client(client, "Too many login attempts!\n");
				return false;
			}
		}
	}

	return false;
}

void *worker_thread(void *arg) {
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

		//printf("[Worker] Handling message: %s\n", task.message);

		if (client->state == INITIAL || client->state == CREATE_USERNAME || \
			client->state == CREATE_PASSWORD || client->state == CREATE_CONFIRM_PASSWORD || \
			client->state == LOGIN_USERNAME || client->state == LOGIN_PASSWORD) {
			if (login_or_signup(client)) {
				char buffer[32]; // 21(max username) + 11 (text below)
				snprintf(buffer, 32, "Welcome, %s!\n", client->username);
				SSL_write(client->ssl, buffer, (int)strlen(buffer));
				printf("[+] Client %d logged in as %s.\n",client->fd,client->username);
				client->state = AUTHENTICATED;
			}
		} else if (client->state == AUTHENTICATED) {
			SSL_write(client->ssl, "Command received.\n", 19);
		}
	}

	printf("[Worker] Thread exiting.\n");
	return NULL;
}

void handle_sigint(int sig) {
	if (sig == 15) {
		printf("\nCaught SIGTERM. Shutting down...\n");
	} else {
		printf("\nCaught SIGINT. Shutting down...\n");
	}
	shutdown_requested = 1;
	pthread_cond_broadcast(&queue_cond);
}

void createopen_db() {
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
		int client_fd = accept(server_fd, NULL, NULL);
		if (client_fd >= 0) {
			if (client_count >= MAX_CLIENTS) {
				fprintf(stderr, "[!] Max clients reached. Rejecting connection (fd: %d).\n", client_fd);
				close(client_fd); // Reject immediately
				return true;
			}
			SSL *ssl = SSL_new(ssl_ctx);
			SSL_set_fd(ssl, client_fd);
			printf("[+] New client connected (fd: %d). Starting SSL handshake...\n", client_fd);

			if (SSL_accept(ssl) <= 0) {
				fprintf(stderr, "[!] SSL_accept failed for fd %d:\n", client_fd);
				ERR_print_errors_fp(stderr);
				SSL_free(ssl);
				close(client_fd);
				return true;
			}

			printf("[+] SSL handshake complete (fd: %d)\n", client_fd);
			make_non_blocking(client_fd);

			if (SSL_write(ssl, "Welcome to the server!\nLogin or signup?\n", 42) <= 0) {
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
				.address = 0,
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
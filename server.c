#include "server.h"

#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#include "sqlite3.h"

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>

// === Globals ===

Client clients[MAX_CLIENTS]; //array of max clients
struct pollfd fds[MAX_CLIENTS + 1]; //array of all possible receiving fds, main tcp and all possible open clients
int client_count = 0;
volatile sig_atomic_t shutdown_requested = 0; //flag to shutdown

Task task_queue[MAX_TASKS]; //circular task queue
int task_front = 0, task_rear = 0; //circular pointers

int udp_broadcast; //udp broadcast fd
Broadcast broadcasts[MAX_BROADCASTS]; //broadcast array
int broadcast_count = 0;

pthread_mutex_t queue_mutex = PTHREAD_MUTEX_INITIALIZER; //mutexes to ensure no race conditions, this one for queue
pthread_cond_t queue_cond = PTHREAD_COND_INITIALIZER; //this one is to hold worker threads idle
pthread_mutex_t client_mutex = PTHREAD_MUTEX_INITIALIZER; //this one protects client array

sqlite3 *db; //pointer to database

// === Main ===

int main() {
	signal(SIGINT, handle_sigint); //install signal handlers for clean shutdown
	signal(SIGTERM, handle_sigint);

	SSL_library_init();
	SSL_load_error_strings();
	OpenSSL_add_ssl_algorithms(); //load ssl
	SSL_CTX *ssl_ctx = create_ssl_context(); //create ssl context, settings for ssl
	SSL_CTX_set_min_proto_version(ssl_ctx, TLS1_2_VERSION);
	SSL_CTX_set_max_proto_version(ssl_ctx, TLS1_3_VERSION); //set tls versions

	create_open_db(); //open database connection

	const int server_fd = socket(AF_INET, SOCK_STREAM, 0); //open tcp socket
	if (server_fd < 0) {
		perror("TCP socket creation failed");
		exit(EXIT_FAILURE);
	}
	udp_broadcast = socket(AF_INET, SOCK_DGRAM, 0); //open udp broadcast socket
	if (udp_broadcast < 0) {
		perror("UDP socket creation failed");
		exit(EXIT_FAILURE);
	}
	struct sockaddr_in addr = {.sin_family = AF_INET, .sin_port = htons(PORT), .sin_addr.s_addr = INADDR_ANY}; //create our ipv4 context
	if (bind(server_fd, (struct sockaddr *) &addr, sizeof(addr)) < 0) { //bind to port
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


	listen(server_fd, 10); //listen, 10 max incoming unaccepted connections
	make_non_blocking(server_fd); //make the serverfd nonblocking

	fds[0].fd = server_fd; //assign the first to the server_fd
	fds[0].events = POLLIN; //set to notify when event happens

	pthread_t pool[THREAD_POOL_SIZE]; //thread pool identifier array, not used much
	for (int i = 0; i < THREAD_POOL_SIZE; ++i) {
		pthread_create(&pool[i], NULL, worker_thread, NULL); //create worker threads and dispatch
	}

	printf("[+] Secure server running on port %d\n", PORT);

	while (!shutdown_requested) { //begin main loop
		int ready = poll(fds, client_count + 1, 1000); //wait 1000 ms for events, if none, run the below anyway
		if (ready < 0)
			continue;

		if (accept_incoming_connections(ssl_ctx, server_fd)) //accept any incoming requests, and skip queueing for this loop
			continue;

		queue_client_task(); //queue any tasks
		kick_idle_clients(); //kick any idle clients
	}

	for (int i = 0; i < THREAD_POOL_SIZE; ++i) {
		pthread_join(pool[i], NULL); //join with all threads
	}

	printf("[*] Shutting down. Disconnecting all clients...\n");
	for (int i = client_count - 1; i >= 0; i--) {
		SSL_write(clients[i].ssl, "eServer shutting down. Goodbye!\n", 33);
		remove_client(i);
	} //disconnect all clients safely

	SSL_CTX_free(ssl_ctx); //free the context
	close(server_fd); //close the server socket
	close(udp_broadcast); //close broadcast socket
	sqlite3_close(db); //close the db
	return 0; //exit
}

// === Signal Handler ===

void handle_sigint(const int sig) {
	if (sig == 15) {
		printf("\nCaught SIGTERM. Shutting down...\n");
	} else {
		printf("\nCaught SIGINT. Shutting down...\n");
	}
	shutdown_requested = 1; //shutdown requested
	pthread_cond_broadcast(&queue_cond); //wake up threads
}


// === Database Management ===

void create_open_db() { //open or create a new database
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
                      active BOOLEAN NOT NULL DEFAULT 1);",
					 NULL, NULL, &zErrMsg) != SQLITE_OK) {
		fprintf(stderr, "Can't create database: %s\n", zErrMsg);
	}

	printf("Connected to database...\n");
}

void update_activity(const char *username) { //updates last activity. Called when a user sends a message/command
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
		// printf("Updated last_activity for user '%s'.\n", username);
	}

	sqlite3_finalize(stmt);
}

void db_client_inactive(const char *username) { //mark a user as inactive in the database. Called when disconnecting a client
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
		// printf("[*] Marked user '%s' as inactive in the database.\n", username);
	}

	sqlite3_finalize(stmt);
}

void db_client_active(const char *username) { //does the opposite, when a client logs in. When they are created, they are created active.
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
		// printf("[*] Marked user '%s' as inactive in the database.\n", username);
	}

	sqlite3_finalize(stmt);
}

// === SSL Utilities ===

SSL_CTX *create_ssl_context() { //tls, private and public keys
	SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
	if (!ctx) {
		fprintf(stderr, "Failed to create SSL context\n");
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}

	if (SSL_CTX_use_certificate_file(ctx, SERVER_CERT, SSL_FILETYPE_PEM) <= 0) { //install certificate
		fprintf(stderr, "Failed to load server certificate from %s\n", SERVER_CERT);
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}

	if (SSL_CTX_use_PrivateKey_file(ctx, SERVER_KEY, SSL_FILETYPE_PEM) <= 0) { //install key
		fprintf(stderr, "Failed to load server key from %s\n", SERVER_KEY);
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}

	return ctx;
}

int shutdown_ssl_gracefully(SSL *ssl, int fd, int timeout_ms) { //attempts to shut down a ssl/tcp connection without closing violently
	struct timeval start, now;
	gettimeofday(&start, NULL);

	while (1) {
		int ret = SSL_shutdown(ssl); //attempt to shut down
		if (ret == 1) //it closed and shut down
			return 1;
		if (ret == 0) //it needs more time to shut down, run loop again
			continue;

		int err = SSL_get_error(ssl, ret); //else error, probably improper shutdown on other side or client has stopped responding
		if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) { //if error is recoverable, wait for client to respond
			gettimeofday(&now, NULL);
			long elapsed = (now.tv_sec - start.tv_sec) * 1000 + (now.tv_usec - start.tv_usec) / 1000;
			if (elapsed > timeout_ms) { //if its taking too long go ahead and close
				fprintf(stderr, "[!] SSL_shutdown timeout on fd %d\n", fd);
				return -1;
			}
			usleep(10000);
		} else { //if not recoverable just go ahead and destroy the socket
			return -1;
		}
	}
}

// === Client Management ===

void remove_client(int i) { //delete a client, and clear related fields
	pthread_mutex_lock(&client_mutex);
	if (i < 0 || i >= client_count || !clients[i].active) { //sometimes this method can be called multiple times on same client, and this makes sure nothing breaks
		pthread_mutex_unlock(&client_mutex);
		return;
	}
	Client *client = &clients[i];

	if (!client->active) {//double sanity check, probably could remove
		pthread_mutex_unlock(&client_mutex);
		return;
	}

	client->active = false; //deactivate it
	db_client_inactive(client->username); //mark inactive in db
	memset(client->username, 0, sizeof(client->username)); //clear username, used for some state detection

	if (client->ssl) { //if there is an active ssl wrapper on the fd
		shutdown_ssl_gracefully(client->ssl, client->fd, 500); //attempt to close it safely
		SSL_free(client->ssl); //free it
		client->ssl = NULL; //clear it
	}

	if (client->fd != -1) { //now close the underlying socket
		close(client->fd);
		client->fd = -1; //set to -1 for safety
	}
	for (int j = i; j < client_count - 1; ++j) { //shift arrays
		clients[j] = clients[j + 1];
		fds[j + 1] = fds[j + 2];
	}

	client_count--; //decrement active clients
	pthread_mutex_unlock(&client_mutex);
}

void disconnect_client(Client *client, const char *reason) { //wrapper for remove client
	if (!client)
		return;

	pthread_mutex_lock(&client_mutex);

	if (!client->active) { //triple sanity check, but technically the first
		pthread_mutex_unlock(&client_mutex);
		return;
	}

	if (reason) //send a nice disconnect reason
		SSL_write(client->ssl, reason, (int) strlen(reason));

	int index = -1; //find the client's index in the clients array
	for (int i = 0; i < client_count; ++i) {
		if (&clients[i] == client) {
			index = i;
			break;
		}
	}

	pthread_mutex_unlock(&client_mutex); //this could be dangerous here if another thread is held before shifting array, but we ball.

	if (index != -1) { //if found
		remove_client(index); // remove
	}
}

void display_clients(const Client *client) { //send the client a basic json list of active clients and let them parse it
	char list[4096] = "d["; //needs big buffer
	bool first = true; //format helper

	pthread_mutex_lock(&client_mutex); //search and locate active clients
	for (int i = 0; i < client_count; i++) {
		if (clients[i].active && clients[i].username[0] != '\0' && &clients[i] != client) {
			if (!first) {
				strcat(list, ",");
			}
			char entry[128];
			snprintf(entry, sizeof(entry), "{\"username\":\"%s\",\"ip\":\"%s\"}", clients[i].username, //make the entry
					 inet_ntoa(clients[i].address.sin_addr));
			strcat(list, entry); //slap the entry on the end
			first = false;
		}
	}
	pthread_mutex_unlock(&client_mutex);

	strcat(list, "]\n");
	SSL_write(client->ssl, list, (int) strlen(list)); //send it on over
}

int make_non_blocking(int fd) { //small helper to make the sslread (or on a lower level, recv) return -1 immediately with EAGAIN if no data
	int flags = fcntl(fd, F_GETFL, 0);
	return fcntl(fd, F_SETFL, flags | O_NONBLOCK); //the magic
}

// === Server I/O ===

void enqueue_task(Task task) { //slap a task on the end of the queue
	pthread_mutex_lock(&queue_mutex);
	task_queue[task_rear] = task;
	task_rear = (task_rear + 1) % MAX_TASKS; //loop the circle if over
	pthread_cond_signal(&queue_cond); //wake up threads
	pthread_mutex_unlock(&queue_mutex);
}

void queue_client_task(void) { //create a task
	for (int i = 0; i < client_count; ++i) {

		Client *client = &clients[i];

		if (fds[i + 1].revents & POLLIN) { //+1 because the clients fd will be shifted one, there is data to read
			int bytes = SSL_read(client->ssl, client->buffer, sizeof(client->buffer) - 1); //read and decrypt

			if (bytes > 0) { //if more than zero bytes were read
				client->buffer[bytes] = '\0'; //append necessary null terminator
				Task task = {client}; //slap the client in the task
				strncpy(task.message, client->buffer, sizeof(task.message) - 1);  //copy message into the task
				enqueue_task(task); //queue it
			} else {
				int err = SSL_get_error(client->ssl, bytes);

				if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) //ignore
					continue;

				if (err == SSL_ERROR_ZERO_RETURN) { //they disconnected
					printf("[-] Client %d disconnected (clean SSL shutdown).\n", client->fd);
				} else { //they disconnected not cleanly
					fprintf(stderr, "[!] SSL_read error on fd %d: code %d\n", client->fd, err);
					ERR_print_errors_fp(stderr);
				}

				remove_client(i); //clean up
				i--; //change index to reflect deleted client
			}
		}
	}
}


void *worker_thread() { //main worker entry point
	while (!shutdown_requested) {//main worker loop
		pthread_mutex_lock(&queue_mutex);
		while (task_front == task_rear && !shutdown_requested) { //while queue is empty
			pthread_cond_wait(&queue_cond, &queue_mutex); //hold the thread idle while no work to do
		}

		if (shutdown_requested) { //if shutting down, exit loop
			pthread_mutex_unlock(&queue_mutex);
			break; //exit main loop
		}

		Task task = task_queue[task_front]; //select a task off the top
		task_front = (task_front + 1) % MAX_TASKS; //move it forward
		pthread_mutex_unlock(&queue_mutex); //unlock so other worker can do work asap

		Client *client = task.client;
		if (!client->active) //if not active, ignore
			continue;

		// printf("[Worker] Handling message: %s\n", task.message);

		if (client->state == INITIAL || client->state == CREATE_USERNAME || client->state == CREATE_PASSWORD ||
			client->state == CREATE_CONFIRM_PASSWORD || client->state == LOGIN_USERNAME ||
			client->state == LOGIN_PASSWORD) { // if in login flow
			if (login_or_signup(client)) { //do the log in flow, returns true if successfully signed in
				db_client_active(client->username); //mark active in db
				char buffer[33]; // 21(max username) + 11 (text below)
				snprintf(buffer, 33, "aWelcome, %s!\n", client->username);
				SSL_write(client->ssl, buffer, (int) strlen(buffer));
				printf("[+] Client %d logged in as %s.\n", client->fd, client->username);
				client->state = AUTHENTICATED;
				send_broadcasts(client, false, NULL); //repeat past 30 minutes of broadcasts
			}
		} else if (client->state == AUTHENTICATED) {
			update_activity(client->username);

			if (client->buffer[0] == 'b') { //check client for all server state codes, but its first letter of each message
				broadcast_message(client, client->buffer + 1); //broadcast message
				SSL_write(client->ssl, "aMessage broadcasted.\n", 23);
			} else if (client->buffer[0] == 'd') {
				display_clients(client); //send client list
			} else if (client->buffer[0] == 'c') { //initiate connection request
				int len = strlen(client->buffer);
				if (len > 0 && client->buffer[len - 1] == '\n') { //remove trailing newline
					client->buffer[len - 1] = '\0';
				}
				struct in_addr target_addr;
				if (inet_pton(AF_INET, client->buffer + 1, &target_addr) <= 0) { //if not a real ip
					pthread_mutex_unlock(&client_mutex);
					SSL_write(client->ssl, "aUser not available.\n", 22);
					break;
				}
				pthread_mutex_lock(&client_mutex); //search for ip
				Client *target = NULL;
				for (int i = 0; i < client_count; i++) {
					if (clients[i].active && (clients[i].address.sin_addr.s_addr == target_addr.s_addr)) {
						target = &clients[i];
						break;
					}
				}

				if (client == target) { //disallow self connection
					pthread_mutex_unlock(&client_mutex);
					SSL_write(client->ssl, "aUser not available.\n", 22);
					break;
				}

				if (target) { //if found
					char buff[1024];
					client->state = IN_HANDOFF; //set to handoff, no exit state
					target->state = D_HANDOFF; //deciding handoff
					client->handoff = target; //set the others handoff pointer
					target->handoff = client;
					snprintf(buff, sizeof(buff), "hConnection request from %s, %s. Accept (y/n)?\n", client->username,
							 inet_ntoa(client->address.sin_addr));
					SSL_write(target->ssl, buff, (int) strlen(buff)); //send the request to the target client
				} else {
					SSL_write(client->ssl, "aUser not available.\n", 22);
				}
				pthread_mutex_unlock(&client_mutex);
			}
		} else if (client->state == D_HANDOFF) { //if you are the deciding client
			update_activity(client->username);

			if (client->buffer[0] == 'h') { //if message was not for handoff, ignore
				if (client->buffer[1] == 'y' || client->buffer[1] == 'Y') { //if accepted
					Client *partner = client->handoff;
					if (partner && partner->active) { //sanity check
						char buf[128];
						snprintf(buf, sizeof(buf), "hConnect to %s:%d\n", inet_ntoa(client->address.sin_addr),
								 ntohs(client->address.sin_port));
						SSL_write(partner->ssl, buf, (int) strlen(buf));

						snprintf(buf, sizeof(buf), "hConnect to %s:%d\n", inet_ntoa(partner->address.sin_addr),
								 ntohs(partner->address.sin_port));
						SSL_write(client->ssl, buf, (int) strlen(buf));

						disconnect_client(partner, NULL); //disconnect both
						disconnect_client(client, NULL);
					}
				} else {
					// Declined
					Client *partner = client->handoff;
					if (partner && partner->active) {
						SSL_write(partner->ssl, "eConnection request declined.\n", 30);
						disconnect_client(partner, NULL); //disconnect the partner
					}
					client->state = AUTHENTICATED; //switch them back to regular state
				}
			}
		}
	}

	printf("[Worker] Thread exiting.\n");
	return NULL;
}

bool accept_incoming_connections(SSL_CTX *ssl_ctx, const int server_fd) {
	if (fds[0].revents & POLLIN) { //if activity on server fd
		struct sockaddr_in cli_addr; //incoming client information
		socklen_t cli_len = sizeof(cli_addr);
		const int client_fd = accept(server_fd, (struct sockaddr *) &cli_addr, &cli_len); //accept it and throw data into cli_addr
		if (client_fd >= 0) { //if it was properly accepted
			if (client_count >= MAX_CLIENTS) { //and space in the server
				fprintf(stderr, "[!] Max clients reached. Rejecting connection (fd: %d).\n", client_fd);
				close(client_fd); // Reject immediately
				return true;
			}
			SSL *ssl = SSL_new(ssl_ctx); //use our previously defined ssl context
			SSL_set_fd(ssl, client_fd); //and assign it to this connection
			printf("[+] New client connected (fd: %d, %d/%d). Starting SSL handshake...\n", client_fd, client_count + 1,
				   MAX_CLIENTS);

			if (SSL_accept(ssl) <= 0) { //now begin ssl handshake, if errors...
				fprintf(stderr, "[!] SSL_accept failed for fd %d:\n", client_fd);
				ERR_print_errors_fp(stderr);//print the errors
				SSL_free(ssl); //clear the ssl socket
				close(client_fd); //close the socket
				return true;
			}

			printf("[+] SSL handshake complete (fd: %d)\n", client_fd); //otherwise connection is now encrypted
			make_non_blocking(client_fd); //make the client socket nonblocking

			if (SSL_write(ssl, "iWelcome to the server!\nLogin or signup?\n", 42) <= 0) { // send initial prompt
				fprintf(stderr, "[!] SSL_write failed after handshake for fd %d:\n", client_fd);
				ERR_print_errors_fp(stderr);
				SSL_shutdown(ssl);
				SSL_free(ssl);
				close(client_fd);
				return true;
			}
			printf("[+] Prompt sent to client %d\n", client_fd);

			clients[client_count] = (Client) {.fd = client_fd, //create client and put it in the array
											  .ssl = ssl,
											  .state = INITIAL,
											  .buffer = {0},
											  .buffer_len = 0,
											  .username = {0},
											  .password = {0},
											  .address = cli_addr,
											  .active = true,
											  .login_attempts = 0};
			fds[client_count + 1].fd = client_fd; //put the fd in the polling array
			fds[client_count + 1].events = POLLIN; //set it for read
			client_count++;
		}
	}
	return false; //no client or successfully created
}

// === Authentication ===

bool login_or_signup(Client *client) { //big finite state machine, returns true when success, false if not
	int msglen = (int) strlen(client->buffer + 1); //go ahead and remove the trailing newline

	if (client->buffer[msglen] == '\n') {
		client->buffer[msglen] = '\0';
		msglen = msglen - 1;
	}

	// signup
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
				memset(client->password, 0, sizeof(client->password)); // clear for security
				client->state = AUTHENTICATED;
				return true;
			}
			SSL_write(client->ssl, "sPasswords do not match! Try again.\nEnter new password:\n", 57);
			memset(client->password, 0, sizeof(client->password));
			client->state = CREATE_PASSWORD;
			return false;
		}
	}

	// login
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

int check_username(const char *username) { //0 if doesnt exist, 1 if true
	sqlite3_stmt *stmt;
	const char *sql = "SELECT 1 FROM users WHERE username = ? LIMIT 1;";

	if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) {
		fprintf(stderr, "Failed to prepare statement: %s\n", sqlite3_errmsg(db));
		return -1; // something broke
	}

	sqlite3_bind_text(stmt, 1, username, -1, SQLITE_STATIC);

	int exists = 0;
	if (sqlite3_step(stmt) == SQLITE_ROW) {
		exists = 1; // username exists
	}

	sqlite3_finalize(stmt);
	return exists;
}

bool check_password(const char *username, const char *password) { //checks the password
	sqlite3_stmt *stmt;
	const char *sql = "SELECT password_hash, password_salt FROM users WHERE username = ? LIMIT 1;";

	if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) {
		fprintf(stderr, "Failed to prepare statement: %s\n", sqlite3_errmsg(db));
		return -1; // something broke
	}

	sqlite3_bind_text(stmt, 1, username, -1, SQLITE_STATIC);

	if (sqlite3_step(stmt) == SQLITE_ROW) {
		const void *password_hash = sqlite3_column_blob(stmt, 0);
		const void *salt = sqlite3_column_blob(stmt, 1);
		hash_and_salt((char *) password, salt); //hash the salt the incoming password

		if (memcmp(password_hash, password, 32) == 0) { //compare the hashes
			sqlite3_finalize(stmt);
			return true;
		}
	}

	sqlite3_finalize(stmt);
	return false;
}

int create_user(const char *username, char *password) { //create a user
	sqlite3_stmt *stmt;
	const char *sql = "INSERT INTO users (username, password_hash, password_salt, last_activity) VALUES (?, ?, ?, "
					  "CURRENT_TIMESTAMP);";

	if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) {
		fprintf(stderr, "Prepare failed: %s\n", sqlite3_errmsg(db));
		return -1;
	}

	sqlite3_bind_text(stmt, 1, username, -1, SQLITE_STATIC);

	const char salt[16];
	RAND_bytes((unsigned char *) salt, 16); //make random for salt
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

int hash_and_salt(char *password, const char *salt) { //hash and salt
	int iterations = 100000;
	int keylen = 32;
	char hash[32];

	if (PKCS5_PBKDF2_HMAC(password, strlen(password), (const unsigned char *) salt, 16, iterations, EVP_sha256(),
						  keylen, (unsigned char *) hash) != 1) { //already have ssl, and this is included in the library
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

// === Broadcast System ===

void send_broadcasts(Client *target, bool send_to_all, const char *single_message) {
	cleanup_broadcasts(); //cleanup old broadcasts before sending out

	pthread_mutex_lock(&client_mutex);
	time_t now = time(NULL);

	if (send_to_all) { //if sending to all (new broadcast)
		for (int i = 0; i < client_count; ++i) { //loop and send
			if (clients[i].active && clients[i].username[0] != 0) {
				struct sockaddr_in udp_addr = clients[i].address;
				udp_addr.sin_port = htons(PORT);
				sendto(udp_broadcast, single_message, strlen(single_message), 0, (struct sockaddr *) &udp_addr,
					   sizeof(udp_addr));
			}
		}
	} else { //needs a target
		if (!target || !target->active) { //if not active
			pthread_mutex_unlock(&client_mutex);
			return;
		}

		for (int i = 0; i < broadcast_count; ++i) { //
			if (now - broadcasts[i].timestamp <= BROADCAST_LIFETIME) { //double check if broadcast is expired
				struct sockaddr_in udp_addr = target->address;
				udp_addr.sin_port = htons(PORT);
				sendto(udp_broadcast, broadcasts[i].message, strlen(broadcasts[i].message), 0,
					   (struct sockaddr *) &udp_addr, sizeof(udp_addr)); //send to target
			}
		}
	}

	pthread_mutex_unlock(&client_mutex);
}

void store_broadcast(const char *sender, const char *msg_body) { //store in array
	cleanup_broadcasts();

	const time_t now = time(NULL);
	const struct tm *local = localtime(&now);
	char time_str[16];
	strftime(time_str, sizeof(time_str), "%-m/%-d %H:%M", local);
	char full_msg[256];
	snprintf(full_msg, sizeof(full_msg), "b[%s %s] %s\n", sender, time_str, msg_body); //store message with timestring

	if (broadcast_count < MAX_BROADCASTS) { //if there is room
		snprintf(broadcasts[broadcast_count].message, sizeof(broadcasts[0].message), "%s", full_msg);
		broadcasts[broadcast_count].timestamp = now;
		broadcast_count++;
	} //else no room

}

void broadcast_message(Client *sender, const char *msg_body) { //wrapper for sending
	printf("[+] User %s broadcasting: %s", sender->username, msg_body);

	store_broadcast(sender->username, msg_body);
	send_broadcasts(NULL, true, broadcasts[broadcast_count - 1].message);
}

void cleanup_broadcasts() {
	const time_t now = time(NULL);
	int new_count = 0;

	for (int i = 0; i < broadcast_count; ++i) { //check time and count living broadcasts
		if (now - broadcasts[i].timestamp <= BROADCAST_LIFETIME) {
			broadcasts[new_count++] = broadcasts[i];
		}
	}
	broadcast_count = new_count;
}

// === Idle Check ===

void kick_idle_clients() { //occasionally called to check activity
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
		const char *username = (const char *) sqlite3_column_text(stmt, 0);

		for (int i = 0; i < client_count; i++) {
			if (clients[i].active && strcmp(clients[i].username, username) == 0) { //sanity check
				printf("[!] Disconnecting idle client %s (timeout).\n", username);
				disconnect_client(&clients[i], "eDisconnected due to inactivity.\n");
				break; //since client list shifts after remove_client()
			}
		}
	}

	pthread_mutex_unlock(&client_mutex);

	sqlite3_finalize(stmt);
}

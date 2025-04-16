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
	bind(server_fd, (struct sockaddr *) &addr, sizeof(addr));
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

		printf("[Worker] Handling message: %s\n", task.message);

		if (client->state == INITIAL) {
			SSL_write(client->ssl, "Welcome, authenticated!\n", 25);
			client->state = AUTHENTICATED;
		} else if (client->state == AUTHENTICATED) {
			SSL_write(client->ssl, "Command received.\n", 18);
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
                      password_hash TEXT NOT NULL, \
                      last_online TIMESTAMP, \
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
	clients[i].active = false;

	int fd = clients[i].fd;
	if (fd == -1) return;

	shutdown_ssl_gracefully(clients[i].ssl, fd, 500);
	SSL_free(clients[i].ssl);
	close(fd);

	for (int j = i; j < client_count - 1; ++j) {
		clients[j] = clients[j + 1];
		fds[j + 1] = fds[j + 2];
	}

	client_count--;
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

			if (SSL_write(ssl, "Initial login state", 16) <= 0) {
				fprintf(stderr, "[!] SSL_write failed after handshake for fd %d:\n", client_fd);
				ERR_print_errors_fp(stderr);
				SSL_shutdown(ssl);
				SSL_free(ssl);
				close(client_fd);
				return true;
			} else {
				printf("[+] Prompt sent to client %d\n", client_fd);
			}

			clients[client_count] = (Client){client_fd, ssl, INITIAL, {0}, 0, true};
			fds[client_count + 1].fd = client_fd;
			fds[client_count + 1].events = POLLIN;
			client_count++;
		}
	}
	return false;
}
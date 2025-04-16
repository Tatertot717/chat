#ifndef SERVER_H
#define SERVER_H
#include <stdbool.h>
#include <openssl/types.h>

#endif //SERVER_H

typedef enum {
	INITIAL, //i
	CREATE_LOGIN, //c
	WAITING_FOR_PASSWORD, //l
	AUTHENTICATED //a
} ClientState;

typedef struct Client {
	int fd;
	SSL *ssl;
	ClientState state;
	char buffer[1024];
	int buffer_len;
	bool active;
} Client;

typedef struct Task {
	Client *client;
	char message[1024];
} Task;

void handle_sigint(int sig);

void createopen_db();

int shutdown_ssl_gracefully(SSL *ssl, int fd, int timeout_ms);

void remove_client(int i);

int make_non_blocking(int fd);

SSL_CTX *create_ssl_context();

void enqueue_task(Task task);

void queue_client_task(void);

void *worker_thread(void *arg);

bool accept_incoming_connections(SSL_CTX *ssl_ctx, int server_fd);
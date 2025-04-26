#ifndef SERVER_H
#define SERVER_H
#include <stdbool.h>
#include <netinet/in.h>
#include <openssl/types.h>

#endif //SERVER_H

typedef enum {
	INITIAL,
	CREATE_USERNAME,
	CREATE_PASSWORD,
	CREATE_CONFIRM_PASSWORD,
	LOGIN_USERNAME,
	LOGIN_PASSWORD,
	AUTHENTICATED,
	IN_HANDOFF,
	D_HANDOFF
} ClientState;

typedef struct Client Client;

struct Client {
	SSL *ssl;
	Client *handoff;
	struct sockaddr_in address;
	int fd;
	ClientState state;
	int buffer_len;
	bool active;
	char login_attempts;
	char username[21];
	char password[32];
	char buffer[1024];
};

typedef struct Task {
	Client *client;
	char message[1024];
} Task;

typedef struct Broadcast{
	char message[256];
	time_t timestamp;
} Broadcast;

void handle_sigint(int sig);

void create_open_db();

int shutdown_ssl_gracefully(SSL *ssl, int fd, int timeout_ms);

void remove_client(int i);

int make_non_blocking(int fd);

SSL_CTX *create_ssl_context();

void enqueue_task(Task task);

void queue_client_task(void);

void *worker_thread();

bool accept_incoming_connections(SSL_CTX *ssl_ctx, int server_fd);

void kick_idle_clients();

void disconnect_client(Client *client, const char *reason);
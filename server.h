#ifndef SERVER_H
#define SERVER_H

#include <netinet/in.h>
#include <openssl/ssl.h>
#include <stdbool.h>

#define PORT 4400
#define MAX_CLIENTS 50
#define THREAD_POOL_SIZE 5
#define MAX_TASKS 100
#define SERVER_CERT "./certs/server.crt"
#define SERVER_KEY "./certs/server.key"
#define MAX_BROADCASTS 100
#define BROADCAST_LIFETIME 1800
#define IDLE_TIMEOUT 3600

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

typedef struct Broadcast {
	char message[256];
	time_t timestamp;
} Broadcast;

// === Functions ===

// Signal handler
void handle_sigint(int sig);

// Database functions
void create_open_db();
void update_activity(const char *username);
void db_client_inactive(const char *username);
void db_client_active(const char *username);

// SSL utilities
int shutdown_ssl_gracefully(SSL *ssl, int fd, int timeout_ms);
SSL_CTX *create_ssl_context();

// Client management
void remove_client(int i);
int make_non_blocking(int fd);
void disconnect_client(Client *client, const char *reason);
void display_clients(const Client *client);

// Server I/O
void enqueue_task(Task task);
void queue_client_task(void);
void *worker_thread();
bool accept_incoming_connections(SSL_CTX *ssl_ctx, int server_fd);

// Authentication
bool login_or_signup(Client *client);
int check_username(const char *username);
bool check_password(const char *username, const char *password);
int create_user(const char *username, char *password);
int hash_and_salt(char *password, const char *salt);

// Broadcast system
void send_broadcasts(Client *target, bool send_to_all, const char *single_message);
void store_broadcast(const char *sender, const char *msg_body);
void broadcast_message(Client *sender, const char *msg_body);
void cleanup_broadcasts();

// Idle check
void kick_idle_clients();

#endif // SERVER_H

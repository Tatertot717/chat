#ifndef CLIENT_H
#define CLIENT_H

// Constants
#define SERVER_IP "172.28.0.10"
#define CLIENT_P2P_PORT 4400
#define HANDOFF_RETRIES 20
#define HANDOFF_DELAY_MS 300

// Connection states
enum HandoffMode {
	NONE,
	CONNECTOR,
	LISTENER
};

// Signal handlers
void handle_signal(int sig);
void handle_resize(int sig);

// UI functions
void init_ui();
void shutdown_ui();
void print_message(const char *msg);

// Networking functions
void *udp_listener(void *arg);
void *receiver(void *arg);
void connect_to_server();
void handle_handoff_message(const char *buffer);

// P2P Handoff functions
void perform_connector_handoff(const char *ip, int port);
void perform_listener_handoff(int port);
int make_certs(SSL_CTX *ctx);

#endif // CLIENT_H
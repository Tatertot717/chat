#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

#define SERVER_IP "172.28.0.10"
#define SERVER_PORT 4400


/* One byte letter message prefix status header
 * i = initial
 * s = signup flow
 * l = login
 * a = authenticated
 * d = display clients
 * b = broadcast to all active clients
 * c = connection request to other client
 * h = handoff flow
 *
 * e = error/exit
 */


void handle_ssl_error(const char *msg) {
    fprintf(stderr, "%s\n", msg);
    ERR_print_errors_fp(stderr);
}

void *udp_listener(void *arg) {
    int udp_sock;
    struct sockaddr_in udp_addr;
    char udp_buffer[1024];

    udp_sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (udp_sock < 0) {
        perror("UDP socket creation failed");
        pthread_exit(NULL);
    }

    memset(&udp_addr, 0, sizeof(udp_addr));
    udp_addr.sin_family = AF_INET;
    udp_addr.sin_addr.s_addr = INADDR_ANY;
    udp_addr.sin_port = htons(SERVER_PORT);

    if (bind(udp_sock, (struct sockaddr*)&udp_addr, sizeof(udp_addr)) < 0) {
        perror("UDP bind failed");
        close(udp_sock);
        pthread_exit(NULL);
    }

    printf("[UDP] Listening for broadcasts on port %d...\n", SERVER_PORT);

    while (1) {
        socklen_t addrlen = sizeof(udp_addr);
        ssize_t len = recvfrom(udp_sock, udp_buffer, sizeof(udp_buffer) - 1, 0,
                               (struct sockaddr*)&udp_addr, &addrlen);
        if (len > 0) {
            udp_buffer[len] = '\0';
            printf("%s\n", udp_buffer);
            fflush(stdout);
        }
    }

    close(udp_sock);
    return NULL;
}

int main() {
    signal(SIGPIPE, SIG_IGN);

    SSL_library_init();
    SSL_load_error_strings();

    const SSL_METHOD *method = TLS_client_method();
    SSL_CTX *ctx = SSL_CTX_new(method);
    if (!ctx) {
        handle_ssl_error("Unable to create SSL context");
        return 1;
    }

    // Start UDP listener thread
    pthread_t udp_thread;
    pthread_create(&udp_thread, NULL, udp_listener, NULL);

    // TCP/SSL part
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in server_addr = {
        .sin_family = AF_INET,
        .sin_port = htons(SERVER_PORT),
    };
    inet_pton(AF_INET, SERVER_IP, &server_addr.sin_addr);

    if (connect(sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) != 0) {
        perror("Connection failed");
        close(sock);
        SSL_CTX_free(ctx);
        return 1;
    }

    SSL *ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sock);

    if (SSL_connect(ssl) <= 0) {
        handle_ssl_error("SSL_connect failed");
        SSL_free(ssl);
        close(sock);
        SSL_CTX_free(ctx);
        return 1;
    }

    char buffer[4096];

    // Initial server message
    int bytes = SSL_read(ssl, buffer, sizeof(buffer) - 1);
    if (bytes > 0) {
        buffer[bytes] = '\0';
        printf("Server: %s", buffer);
    } else {
        handle_ssl_error("Failed to read server prompt");
        goto cleanup;
    }

    while (1) {
        printf("\nEnter message (prefix 'l' for login, 's' for signup, 'b' to broadcast): ");
        if (fgets(buffer, sizeof(buffer), stdin) == NULL) break;

        if (strncmp(buffer, "exit", 4) == 0) break;

        int sent = SSL_write(ssl, buffer, strlen(buffer));
        if (sent <= 0) {
            handle_ssl_error("SSL_write failed");
            break;
        }

        bytes = SSL_read(ssl, buffer, sizeof(buffer) - 1);
        if (bytes > 0) {
            buffer[bytes] = '\0';
            printf("Server: %s", buffer);
        } else {
            handle_ssl_error("SSL_read failed");
            break;
        }
    }

cleanup:
    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(sock);
    SSL_CTX_free(ctx);
    return 0;
}

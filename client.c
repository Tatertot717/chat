#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

#define SERVER_IP "127.0.0.1"
#define SERVER_PORT 4400

void handle_ssl_error(const char *msg) {
    fprintf(stderr, "%s\n", msg);
    ERR_print_errors_fp(stderr);
}

int main() {
    // Prevent crashes on SIGPIPE (when writing to closed socket)
    signal(SIGPIPE, SIG_IGN);

    SSL_library_init();
    SSL_load_error_strings();

    const SSL_METHOD *method = TLS_client_method();
    SSL_CTX *ctx = SSL_CTX_new(method);
    if (!ctx) {
        handle_ssl_error("Unable to create SSL context");
        return 1;
    }

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

    char buffer[1024];

    // Read initial server prompt
    int bytes = SSL_read(ssl, buffer, sizeof(buffer) - 1);
    if (bytes > 0) {
        buffer[bytes] = '\0';
        printf("Server: %s", buffer);
    } else {
        handle_ssl_error("Failed to read server prompt");
        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(sock);
        SSL_CTX_free(ctx);
        return 1;
    }

    // Send a username
    printf("Enter username to send: ");
    if (fgets(buffer, sizeof(buffer), stdin) == NULL) {
        printf("Input error.\n");
        goto cleanup;
    }

    int sent = SSL_write(ssl, buffer, strlen(buffer));
    if (sent <= 0) {
        handle_ssl_error("SSL_write failed");
        goto cleanup;
    }

    // Read response from server
    bytes = SSL_read(ssl, buffer, sizeof(buffer) - 1);
    if (bytes > 0) {
        buffer[bytes] = '\0';
        printf("Server: %s", buffer);
    } else {
        handle_ssl_error("Failed to read server response");
    }

cleanup:
    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(sock);
    SSL_CTX_free(ctx);
    return 0;
}

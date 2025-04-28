#include <arpa/inet.h>
#include <fcntl.h>
#include <ncurses.h>
#include <netinet/in.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "client.h"
#include "server.h"

/* One byte letter message prefix status header
 * i = initial
 * s = signup flow
 * l = login
 * a = authenticated
 * d = display clients
 * b = broadcast to all active clients
 * c = connection request to other client
 * h = handoff flow
 * w = waiting for accept/decline
 * p = peer mode
 * y = your messages, ignore
 *
 * e = error/exit
 */

// UI WINDOWS
WINDOW *message_win, *input_win; // top and bottom window

// GLOBALS
int tcp_sock; // connection to other, can be either peer or server
SSL *ssl; // ssl context for the tcp sock
SSL_CTX *ctx; // contains the context for ssl, client/server.

volatile int shutdown_req = 0; // shutdown signal
pthread_mutex_t ui_mutex =
		PTHREAD_MUTEX_INITIALIZER; // ui mutex, sometimes race conditions if multiple come in at same time

pthread_t udp_thread, recv_thread; // async receiving
char current_state = 'i'; // set to inital state
char pending_command = 0; // set no pending command
int input_locked = 0; // input unlockec
int udp_sock = -1; // no valid sock yet
int in_p2p_mode = 0; // not in p2p
char peer_username[64] = {0}; // no peer username
int client_server_port = 0; // no port yet
enum HandoffMode handoff_mode = NONE; // not in a handoff

// SIGNALS
void handle_signal(int sig) { shutdown_req = 1; } // safe shutdown

void handle_resize(int sig) { // window resizing redraw, I don't store the incoming buffer so it will clear on resize.
	pthread_mutex_lock(&ui_mutex);
	endwin(); // closes existing windows
	refresh(); // refreshes the screen
	clear(); // clears

	int height = LINES - 3; // finds how big it is now

	if (message_win) {
		delwin(message_win); // delete the windows
	}
	if (input_win) {
		delwin(input_win);
	}

	message_win = newwin(height, COLS, 0, 0); // recreate them at proper sizes
	scrollok(message_win, TRUE);

	input_win = newwin(3, COLS, height, 0);
	box(input_win, 0, 0); // draw the box around the input box
	wmove(input_win, 1, 1);
	wrefresh(input_win); // now redraw it

	flushinp(); // flush input buffer
	pthread_mutex_unlock(&ui_mutex);
}

// MAIN
int main() {
	signal(SIGPIPE, SIG_IGN); // ignore a broken pipe, can occasionally happen.
	signal(SIGINT,
		   handle_signal); // basic interrupt handlers, although it's not possible in terminal since I capture all input
	signal(SIGQUIT, handle_signal);
	signal(SIGTERM, handle_signal);

	SSL_library_init();
	SSL_load_error_strings();

	ctx = SSL_CTX_new(TLS_client_method()); // be a client, no certs required
	if (!ctx) {
		ERR_print_errors_fp(stderr);
		return 1;
	}

	connect_to_server(); // connect to the server
	init_ui(); // initialize cool ui
	signal(SIGWINCH, handle_resize); // install window resize handler, now that ncurses is running

	pthread_create(&recv_thread, NULL, receiver, NULL); // create the async comms threads
	pthread_create(&udp_thread, NULL, udp_listener, NULL);

	char input_buffer[1024] = {0}; // the input buffer
	int input_len = 0; // current length of input

	halfdelay(1); // 0.1s input timeout, keeps stuff synced

	while (!shutdown_req) {
		pthread_mutex_lock(&ui_mutex); // lock ui while drawing over it
		werase(input_win);
		box(input_win, 0, 0); // redraw box

		if (input_locked) { // draw the helpful input hints
			mvwprintw(input_win, 0, 2, " Waiting for peer... ");
		} else if (pending_command == 'b') {
			mvwprintw(input_win, 0, 2, " Broadcast message: ");
		} else if (pending_command == 'c') {
			mvwprintw(input_win, 0, 2, " Connect to (IP): ");
		} else {
			switch (current_state) {
				case 'i':
					mvwprintw(input_win, 0, 2, " (l)ogin or (s)ignup ");
					break;
				case 'a':
					mvwprintw(input_win, 0, 2, " (d)isplay, (c)onnect, (b)roadcast ");
					break;
				case 'h':
					mvwprintw(input_win, 0, 2, " Accept connection? (y/n) ");
				default:
					mvwprintw(input_win, 0, 2, " Type your message ");
					break;
			}
		}


		wmove(input_win, 1, 1); // move inside box
		wclrtoeol(input_win); // clear from cursor to end of line

		mvwprintw(input_win, 1, 1, "%s", input_buffer); // print the input buffer
		wmove(input_win, 1, 1 + input_len); // move cursor
		wrefresh(input_win);
		pthread_mutex_unlock(&ui_mutex); // unlock ui

		curs_set(1); // shows the cursor
		int ch = wgetch(input_win); // wait for user input
		curs_set(0); // hides cursor

		if (ch == ERR) { // something broke, ignore it
			continue;
		}

		if (input_locked) { // input is locked, ignore
			continue;
		}


		if (ch == 3 || ch == 4 || ch == 24) { // ^C ^D ^X
			shutdown_req = 1;
			break;
		}

		if (ch == '\n') { // enter handler, aka command/message complete
			if (input_len > 0) {
				input_buffer[input_len] = '\0';

				char local_echo[1024];
				local_echo[0] = 'y'; // prefix for your own messages
				memcpy(local_echo + 1, input_buffer, input_len + 1); // include the null terminator
				print_message(local_echo);

				// now begin parsing of command
				if (current_state == 'h') {
					if (input_len == 1 && (input_buffer[0] == 'y' || input_buffer[0] == 'n')) {
						if (handoff_mode == NONE)
							handoff_mode = CONNECTOR;
						char send_buffer[3];
						send_buffer[0] = 'h'; // always prefix handoff reply
						send_buffer[1] = input_buffer[0];
						send_buffer[2] = '\0';

						if (SSL_write(ssl, send_buffer, 2) <= 0) {
							shutdown_req = 1;
							break;
						}

						input_len = 0;
						memset(input_buffer, 0, sizeof(input_buffer));
						continue;
					}
					// invalid response, prompt again
					memset(input_buffer, 0, sizeof(input_buffer));
					input_len = 0;
					continue;
				}

				// handling for initial login/signup mode
				if (pending_command == 0 && current_state == 'i') {
					if (input_len == 1 && (input_buffer[0] == 'l' || input_buffer[0] == 's')) {
						char send_buffer[2];
						send_buffer[0] = input_buffer[0];
						send_buffer[1] = '\0';
						if (SSL_write(ssl, send_buffer, 1) <= 0) {
							shutdown_req = 1;
							break;
						}
						input_len = 0;
						memset(input_buffer, 0, sizeof(input_buffer));
						continue;
					}
				}

				// special handling for authenticated menu (d/c/b)
				if (pending_command == 0 && current_state == 'a') {
					if (input_len == 1 &&
						(input_buffer[0] == 'd' || input_buffer[0] == 'c' || input_buffer[0] == 'b')) {
						pending_command = input_buffer[0];
						if (pending_command != 'd') {
							if (pending_command == 'c')
								if (handoff_mode == NONE)
									handoff_mode = LISTENER;
							input_len = 0;
							memset(input_buffer, 0, sizeof(input_buffer));
							continue; // wait for second input
						}
					}
				}

				// regular message sending
				char send_buffer[1024];
				if (pending_command != 0) {
					send_buffer[0] = pending_command;
				} else {
					send_buffer[0] = current_state;
				}
				memcpy(send_buffer + 1, input_buffer, input_len);

				if (SSL_write(ssl, send_buffer, input_len + 1) <= 0) {
					shutdown_req = 1;
					break;
				}

				input_len = 0;
				pending_command = 0;
				memset(input_buffer, 0, sizeof(input_buffer));
			}
		}

		if (ch == KEY_BACKSPACE || ch == 127) { // delete from input buffer
			if (input_len > 0) {
				input_len--;
				input_buffer[input_len] = '\0';
			}
		} else if (input_len < sizeof(input_buffer) - 1) { // if not full
			if (ch != '\n' && ch != '\r') { // Only allow real visible characters
				input_buffer[input_len++] = ch; // put in the buffer
			}
		}
	}

	// Shutdown sequence
	shutdown_req = 1;
	pthread_cancel(recv_thread);
	pthread_join(recv_thread, NULL);

	if (!in_p2p_mode) { // udp is shutdown if in p2p, so don't need to do it again
		pthread_cancel(udp_thread);
		pthread_join(udp_thread, NULL);
	}

	fcntl(tcp_sock, F_SETFL, O_NONBLOCK); // if the other side holds, it might get stuck forever trying to close

	if (ssl) {
		SSL_shutdown(ssl); // call it twice because you're supposed to, first one is requesting
		SSL_shutdown(ssl); // second one closes
		SSL_free(ssl);
	}
	if (tcp_sock >= 0) {
		close(tcp_sock);
	}
	if (ctx) {
		SSL_CTX_free(ctx);
	}

	shutdown_ui();
	return 0;
}

// NCURSES UI
void init_ui() {
	initscr(); // initialize
	if (has_colors()) { // if the display supports colors
		start_color(); // use it
		init_pair(1, COLOR_GREEN, COLOR_BLACK); // and have green text, with black bg.
	}
	cbreak(); // inbetween raw and line mode, get parsed chars instantly from console
	noecho(); // shut off automatic drawing, we do our own input box
	curs_set(1);

	int height = LINES - 3;
	message_win = newwin(height, COLS, 0, 0);
	scrollok(message_win, TRUE); // allow scrolling in the history box, when it fills up

	input_win = newwin(3, COLS, height, 0);
	box(input_win, 0, 0);
	wmove(input_win, 1, 1);
	wrefresh(input_win);
}

void shutdown_ui() {
	delwin(message_win);
	delwin(input_win);
	endwin(); // set everything back to normal
}

void print_message(const char *msg) { // since all input flows through here, I use it to set the state machine
	pthread_mutex_lock(&ui_mutex);

	if (strlen(msg) < 2) { // first character is always control character, so if only one character, then it was garbage
		pthread_mutex_unlock(&ui_mutex);
		return;
	}

	if (msg[0] != 'y') { // ignore own messages
		current_state = msg[0];
	}

	// Set typing lock based on state
	if (current_state == 'w') {
		input_locked = 1;
	} else {
		input_locked = 0;
	}

	if (current_state == 'd' || current_state == 'b') { // these loop back to auth
		current_state = 'a';
	}

	const char *body = msg + 1; // skip prefix

	if (msg[0] == 'y') { // print own messages with COLOR
		wattron(message_win, COLOR_PAIR(1));
		wprintw(message_win, "You: %s\n", msg + 1);
		wattroff(message_win, COLOR_PAIR(1));
		wrefresh(message_win);
		wmove(input_win, 1, 1);
		wrefresh(input_win);

		pthread_mutex_unlock(&ui_mutex);
		return;
	}
	if (msg[0] == 'd' && body[0] == '[') { // special handling for json object
		wprintw(message_win, "Server:\n     Active Clients:\n");

		const char *p = body;
		while ((p = strstr(p, "{\"username\":\"")) != NULL) {
			p += strlen("{\"username\":\"");
			const char *user_end = strchr(p, '"');
			if (!user_end)
				break;

			char username[64] = {0};
			strncpy(username, p, user_end - p);

			p = strstr(user_end, "\"ip\":\"");
			if (!p)
				break;
			p += strlen("\"ip\":\"");
			const char *ip_end = strchr(p, '"');
			if (!ip_end)
				break;

			char ip[64] = {0};
			strncpy(ip, p, ip_end - p);

			wprintw(message_win, "- %s (%s)\n", username, ip);

			p = ip_end;
		}
	} else if (in_p2p_mode == 0) {
		wprintw(message_win, "Server: %s\n", body); // append server
	} else {
		wprintw(message_win, "%s: %s\n", peer_username, body); // append user
	}

	// Clear input immediately if interrupt (handoff request or waiting)
	if (msg[0] == 'h' || msg[0] == 'w') {
		pending_command = 0;
		current_state = msg[0]; // 'h' or 'w'
	}

	pending_command = 0; // reset pending command, as it now has gone through
	wrefresh(message_win);
	wmove(input_win, 1, 1);
	wrefresh(input_win);

	pthread_mutex_unlock(&ui_mutex);
}

// NETWORKING
void *udp_listener(void *arg) { // broadcast receiver
	char buffer[1024];

	udp_sock = socket(AF_INET, SOCK_DGRAM, 0); // use udp
	if (udp_sock < 0)
		pthread_exit(NULL);

	struct sockaddr_in listen_addr = {0};
	listen_addr.sin_family = AF_INET;
	listen_addr.sin_addr.s_addr = INADDR_ANY;
	listen_addr.sin_port = htons(client_server_port); // use the random port, but same as tcp

	if (bind(udp_sock, (struct sockaddr *) &listen_addr, sizeof(listen_addr)) < 0) {
		perror("UDP bind failed");
		close(udp_sock);
		pthread_exit(NULL);
	}

	while (!shutdown_req && !in_p2p_mode) { // either exits
		ssize_t len = recvfrom(udp_sock, buffer, sizeof(buffer) - 1, 0, NULL, NULL);
		if (len > 0) {
			buffer[len] = '\0';
			print_message(buffer);
		}
	}

	close(udp_sock);
	pthread_exit(NULL);
}

void *receiver(void *arg) { // this receives ssl on the tcp
	char buffer[4096];

	while (!shutdown_req) {
		int bytes = SSL_read(ssl, buffer, sizeof(buffer) - 1);
		if (bytes <= 0) {
			shutdown_req = 1;
			break;
		}

		buffer[bytes] = '\0'; // set the end, could still have bytes in it from last read

		if (buffer[0] == 'h' && strstr(buffer, "Connect to ") == buffer + 1) { // intercept switch message
			in_p2p_mode = 1;
			handle_handoff_message(buffer);
		} else {
			print_message(buffer);
		}
	}

	pthread_exit(NULL);
}

void connect_to_server() {
	const int retry_delays[] = {10, 30, 60, 300, 600}; // seconds
	const int max_retries = sizeof(retry_delays) / sizeof(retry_delays[0]); // find out how many are in the above array

	for (int attempt = 0; attempt <= max_retries; attempt++) { // retry if error
		tcp_sock = socket(AF_INET, SOCK_STREAM, 0); // use tcp
		if (tcp_sock < 0) {
			perror("Socket creation failed");
			exit(1);
		}

		struct sockaddr_in local_addr = {0};
		local_addr.sin_family = AF_INET;
		local_addr.sin_addr.s_addr = INADDR_ANY;

		if (bind(tcp_sock, (struct sockaddr *) &local_addr, sizeof(local_addr)) < 0) {
			perror("TCP bind failed");
			exit(1);
		}

		struct sockaddr_in assigned_addr;
		socklen_t len = sizeof(assigned_addr);
		if (getsockname(tcp_sock, (struct sockaddr *) &assigned_addr, &len) == 0) {
			client_server_port = ntohs(assigned_addr.sin_port);
		} else {
			perror("getsockname failed");
			exit(1);
		}

		struct sockaddr_in server_addr = {0};
		server_addr.sin_family = AF_INET;
		server_addr.sin_port = htons(SERVER_PORT); // 4400
		inet_pton(AF_INET, SERVER_IP, &server_addr.sin_addr);

		if (connect(tcp_sock, (struct sockaddr *) &server_addr, sizeof(server_addr)) < 0) {
			perror("Connect");
			exit(1);
		}

		ssl = SSL_new(ctx); // initialize ssl based on the parameters in ctx
		SSL_set_fd(ssl, tcp_sock); // assign it to our server

		if (SSL_connect(ssl) <=
			0) { // the server accepts the connection but immediately closes it if full, so the ssl handshake will fail
			fprintf(stderr, "SSL_connect failed, server probably full. Attempt %d/%d\n", attempt + 1, max_retries + 1);
			ERR_print_errors_fp(stderr);

			SSL_free(ssl);
			close(tcp_sock);

			if (attempt == max_retries) {
				fprintf(stderr, "Maximum retries reached. Giving up.\n");
				exit(1);
			}

			sleep(retry_delays[attempt]); // sleep for predetermined time, increases each time
			continue;
		}

		printf("Connected to server successfully.\n");
		return;
	}
}

void handle_handoff_message(const char *buffer) {
	const char *connect_info = buffer + strlen("hConnect to "); // slide it over
	char ip[64] = {0};
	char username[64] = {0};
	int port = 0;

	if (sscanf(connect_info, "%63[^:]:%d:%63[^\n]", ip, &port, username) !=
		3) { // extract ip, port and username, port should always be 4400
		print_message("eInvalid connect info received.\n");
		shutdown_req = 1;
		return;
	}

	strncpy(peer_username, username, sizeof(peer_username)); // copy username
	peer_username[sizeof(peer_username) - 1] = '\0';


	print_message("hSwitching to peer-to-peer mode...\n");

	if (handoff_mode == CONNECTOR) {
		// Only the connector closes immediately, has to create a new socket to connect to peer
		if (ssl) {
			SSL_shutdown(ssl);
			SSL_shutdown(ssl);
			SSL_free(ssl);
			ssl = NULL;
		}
		if (tcp_sock >= 0) {
			close(tcp_sock);
			tcp_sock = -1;
		}
		perform_connector_handoff(ip, port);
	} else if (handoff_mode == LISTENER) {
		perform_listener_handoff(port);
	} else {
		print_message("eUnknown handoff mode.\n");
		shutdown_req = 1;
	}

	current_state = 'p';
	print_message("pSuccessfully connected to peer!\n");
}

// HANDOFF
int make_certs(SSL_CTX *ctx) { // this creates some in memory certs, to keep encrypted channel, there are better ways to
							   // do this, but this is the way I know how to
	/* https://github.com/openssl/openssl/tree/master/demos */
	EVP_PKEY *pkey = NULL; // our private key
	X509 *x509 = NULL; // our cert

	// create RSA key using EVP
	pkey = EVP_RSA_gen(2048); // doesnt have to be long
	if (!pkey)
		return 0;

	// create minimal X509 certificate, doesnt have to contain anything since I don't validate it
	x509 = X509_new();
	if (!x509) {
		EVP_PKEY_free(pkey); // release our private key from it
		return 0;
	}

	X509_set_version(x509, 2); // v3 cert
	ASN1_INTEGER_set(X509_get_serialNumber(x509), 1);
	X509_gmtime_adj(X509_get_notBefore(x509), 0);
	X509_gmtime_adj(X509_get_notAfter(x509), 3600); // valid 1 hour

	X509_set_pubkey(x509, pkey); // generate a public key based on our cert

	// empty subject/issuer still needed
	X509_NAME *name = X509_NAME_new();
	if (!name) {
		EVP_PKEY_free(pkey);
		X509_free(x509);
		return 0;
	}
	X509_set_subject_name(x509, name); // blank
	X509_set_issuer_name(x509, name);
	X509_NAME_free(name); // clear name pointer

	if (!X509_sign(x509, pkey, EVP_sha256())) { // sign it and finish the cert
		EVP_PKEY_free(pkey);
		X509_free(x509);
		return 0;
	}

	// set cert and key into SSL_CTX
	if (SSL_CTX_use_certificate(ctx, x509) != 1 || SSL_CTX_use_PrivateKey(ctx, pkey) != 1) {
		EVP_PKEY_free(pkey);
		X509_free(x509);
		return 0;
	}


	EVP_PKEY_free(pkey);
	X509_free(x509);
	return 1;
}

void perform_connector_handoff(const char *ip, int port) { // connect to the listener
	struct sockaddr_in peer_addr;
	int sock = socket(AF_INET, SOCK_STREAM, 0); // make a new socket

	if (sock < 0) {
		print_message("eSocket creation failed.\n");
		shutdown_req = 1;
		return;
	}

	memset(&peer_addr, 0, sizeof(peer_addr)); // zero peer
	peer_addr.sin_family = AF_INET; // fill it with what we want
	peer_addr.sin_port = htons(port);
	inet_pton(AF_INET, ip, &peer_addr.sin_addr); // use the port provided, should be 4400

	int attempt; // sometimes it takes a minute for the listener to get ready, so just add some delay and retry until
				 // its ready
	for (attempt = 0; attempt < HANDOFF_RETRIES; ++attempt) {
		if (connect(sock, (struct sockaddr *) &peer_addr, sizeof(peer_addr)) == 0) {
			break;
		}
		usleep(HANDOFF_DELAY_MS * 1000);
	}

	if (attempt == HANDOFF_RETRIES) {
		print_message("eFailed to connect to peer after retries.\n");
		close(sock);
		shutdown_req = 1;
		return;
	}

	SSL *new_ssl = SSL_new(ctx); // now reinitialize ssl
	SSL_set_fd(new_ssl, sock);

	if (SSL_connect(new_ssl) <= 0) {
		print_message("eSSL connect to peer failed.\n");
		SSL_free(new_ssl);
		close(sock);
		shutdown_req = 1;
		return;
	}

	// successful, replace globals

	ssl = new_ssl;
	tcp_sock = sock;
	in_p2p_mode = 1;
}

void perform_listener_handoff(int port) {
	int listen_sock = socket(AF_INET, SOCK_STREAM, 0);
	if (listen_sock < 0) {
		print_message("eSocket creation failed.\n");
		shutdown_req = 1;
		return;
	}

	int opt = 1;
	setsockopt(listen_sock, SOL_SOCKET, SO_REUSEADDR, &opt,
			   sizeof(opt)); // this is an artifact of when I tried to use port 4400 for everything
	setsockopt(listen_sock, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt)); // TIME_WAIT really did not want me to do that

	struct sockaddr_in listen_addr = {0};
	listen_addr.sin_family = AF_INET;
	listen_addr.sin_addr.s_addr = INADDR_ANY;
	listen_addr.sin_port = htons(port);

	if (bind(listen_sock, (struct sockaddr *) &listen_addr, sizeof(listen_addr)) < 0) {
		print_message("eListener bind failed.\n");
		close(listen_sock);
		shutdown_req = 1;
		return;
	}

	listen(listen_sock, 1); // listen for new incoming connection

	struct sockaddr_in incoming_addr;
	socklen_t incoming_len = sizeof(incoming_addr);
	int new_sock = accept(listen_sock, (struct sockaddr *) &incoming_addr, &incoming_len); // only accept once

	close(listen_sock);

	if (new_sock < 0) {
		print_message("eFailed to accept peer connection.\n");
		shutdown_req = 1;
		return;
	}

	SSL_CTX_free(ctx); // reinitialize ssl context
	ctx = SSL_CTX_new(TLS_server_method()); // set to server, since we listen
	make_certs(ctx); // now need to generate some certs, since we are the "server"
	SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
	SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);
	SSL *new_ssl = SSL_new(ctx);
	SSL_set_fd(new_ssl, new_sock);

	if (SSL_accept(new_ssl) <= 0) {
		print_message("eSSL accept from peer failed.\n");
		ERR_print_errors_fp(stderr);
		SSL_free(new_ssl);
		close(new_sock);
		shutdown_req = 1;
		return;
	}

	// now safe to shut down old connection
	if (ssl) {
		SSL_shutdown(ssl);
		SSL_shutdown(ssl);
		SSL_free(ssl);
	}
	if (tcp_sock >= 0) {
		close(tcp_sock);
	}

	ssl = new_ssl;
	tcp_sock = new_sock;
	in_p2p_mode = 1;
}

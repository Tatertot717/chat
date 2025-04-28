# Compiler and tools
CC := gcc
CFLAGS := -Wall

DEBUG_FLAGS := -g -Og
RELEASE_FLAGS := -O3 -march=native

SQLITE_LIBS := -lpthread -ldl -lm
OPENSSL_LIBS := -lssl -lcrypto -lpthread
NCURSES_LIBS := -lncurses

# Definitions
BUILD_DIR := build
CERT_DIR := certs
OBJ_DIR := $(BUILD_DIR)/obj
DEBUG_DIR := $(BUILD_DIR)/debug
RELEASE_DIR := $(BUILD_DIR)/release
SERVER_DB := server.db

# Source files
CLIENT_SRC := client.c
SERVER_SRC := server.c sqlite3.c
SHELL_SRC := shell.c sqlite3.c

# Object files
CLIENT_OBJS_DBG := $(OBJ_DIR)/client_dbg.o
SERVER_OBJS_DBG := $(OBJ_DIR)/server_dbg.o $(OBJ_DIR)/sqlite3.o

CLIENT_OBJS_REL := $(OBJ_DIR)/client.o
SERVER_OBJS_REL := $(OBJ_DIR)/server.o $(OBJ_DIR)/sqlite3.o
SHELL_OBJS_REL  := $(OBJ_DIR)/shell.o $(OBJ_DIR)/sqlite3.o

# Targets
CLIENT_DBG := $(DEBUG_DIR)/client
SERVER_DBG := $(DEBUG_DIR)/server

CLIENT_REL := $(RELEASE_DIR)/client
SERVER_REL := $(RELEASE_DIR)/server
SHELL_REL  := $(RELEASE_DIR)/shell

.PHONY: all debug release clean client server shell

all: debug release

debug: $(CLIENT_DBG) $(SERVER_DBG) $(SHELL_REL)
release: $(CLIENT_REL) $(SERVER_REL)

# Individual targets
client: $(CLIENT_REL)
server: $(SERVER_REL)
shell:  $(SHELL_REL)

# Debug executables
$(CLIENT_DBG): $(CLIENT_OBJS_DBG)
	@mkdir -p $(DEBUG_DIR)
	$(CC) -o $@ $^ $(OPENSSL_LIBS) $(NCURSES_LIBS)

$(SERVER_DBG): $(SERVER_OBJS_DBG)
	@mkdir -p $(DEBUG_DIR)
	$(CC) -o $@ $^ $(SQLITE_LIBS) $(OPENSSL_LIBS)
	./cert.sh

# Release executables
$(CLIENT_REL): $(CLIENT_OBJS_REL)
	@mkdir -p $(RELEASE_DIR)
	$(CC) -o $@ $^ $(OPENSSL_LIBS) $(NCURSES_LIBS)

$(SERVER_REL): $(SERVER_OBJS_REL)
	@mkdir -p $(RELEASE_DIR)
	$(CC) -o $@ $^ $(SQLITE_LIBS) $(OPENSSL_LIBS)
	./cert.sh

$(SHELL_REL): $(SHELL_OBJS_REL)
	@mkdir -p $(RELEASE_DIR)
	$(CC) -o $@ $^ $(SQLITE_LIBS)

# Object file rules
$(OBJ_DIR)/%.o: %.c
	@mkdir -p $(OBJ_DIR)
	$(CC) $(CFLAGS) $(RELEASE_FLAGS) -c -o $@ $<

$(OBJ_DIR)/%_dbg.o: %.c
	@mkdir -p $(OBJ_DIR)
	$(CC) $(CFLAGS) $(DEBUG_FLAGS) -c -o $@ $<

# sqlite3 always uses -O3 regardless of mode
$(OBJ_DIR)/sqlite3.o: sqlite3.c
	@mkdir -p $(OBJ_DIR)
	$(CC) $(CFLAGS) $(RELEASE_FLAGS) -c -o $@ $<

$(OBJ_DIR)/shell.o: shell.c
	@mkdir -p $(OBJ_DIR)
	$(CC) $(CFLAGS) $(RELEASE_FLAGS) -c -o $@ $<


clean:
	rm -rf $(BUILD_DIR)
	rm -rf $(CERT_DIR)
	rm -rf $(SERVER_DB)

cleanexec:
	rm -rf $(BUILD_DIR)/debug
	rm -rf $(BUILD_DIR)/release
	rm -rf $(CERT_DIR)
	rm -rf $(SERVER_DB)


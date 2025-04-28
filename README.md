# P2P Chat App with Server

A simple and secure peer-to-peer (P2P) chat application.  
Features:

- **OpenSSL** encryption for secure message transmission
- **SQLite3** backend for user management
- **ncurses** front-end for a dynamic terminal UI
- **Dockerized** environment for easy setup
- **P2P direct handoff** between clients after server authentication
- **Broadcast system** for real-time server updates

---

## Building

### Using Docker (Recommended)
In the project directory:

```bash
./run.sh
```

This will build and launch a Docker container with all necessary dependencies.

### Manual Build
Ensure you have the following packages installed:

- `openssl`
- `libssl-dev`
- `libncurses-dev`
- `ncurses-bin`
- `build-essential`

Then:

```bash
make release
```

This builds an optimized release version under `build/release/`.

---

## Running

### Standalone
Run the binaries manually from the `build/release/` directory.

### Using Docker Compose
- The **server** starts automatically inside the server container.
- Use:

```bash
./clientconnect.sh [client number]
```

to open and connect a client automatically.

---

## Features

- **Secure SSL/TLS Connections:**  
  Using OpenSSL with enforced TLS 1.2 and 1.3 protocols.

- **User Authentication System:**
    - Secure password hashing with PBKDF2.
    - Signup and login flows.
    - SQLite3 database-backed authentication.

- **Dynamic UI with ncurses:**
    - Message window and input box
    - Smooth resizing support
    - Colored messages for self and peer differentiation

- **Real-time Server Broadcasting:**
    - Active users list
    - Message broadcasting to all users via UDP

- **Peer-to-Peer Connection Handoff:**
    - Direct encrypted communication without server relay.
    - In-memory certificate generation for P2P SSL encryption.

- **Idle Timeout Handling:**  
  Clients are automatically disconnected after inactivity.

---

## Quick Overview of the Protocol

Single-character prefix-based message system:

| Prefix | Meaning                             |
|:------:|:------------------------------------|
|  `i`   | Initial welcome/login/signup prompt |
|  `s`   | Signup flow prompts                 |
|  `l`   | Login flow prompts                  |
|  `a`   | Authenticated state messages        |
|  `d`   | Active clients list                 |
|  `b`   | Broadcast messages                  |
|  `c`   | Connection request to a client      |
|  `h`   | Handoff connection request/response |
|  `w`   | Waiting for peer response           |
|  `p`   | Peer mode messages                  |
|  `y`   | Your own messages (local echo)      |
|  `e`   | Error or exit messages              |

---

## Project Structure

- `server.c` – Secure server handling authentication, task queue, broadcasts, and client management.
- `client.c` – Interactive ncurses-based client with server and P2P communication handling.
- `server.h`, `client.h` – Headers defining core structures and constants.
- `run.sh` – Script to build and launch using Docker.
- `clientconnect.sh` – Helper to connect to clients in Docker.

---

## Docker
```bash
./run.sh
```
- Installs dependencies
- Compiles code
- Spins up isolated server and clients, scale-able for testing in the docker-compose.yml file

---

## Requirements

- Linux (tested on Ubuntu 24.10)
- Docker (for easiest experience)
- gcc 14.2
- ncurses 6.5-2
- OpenSSL 3.3.1 4
- SQLite3 (bundled)
---

## Uninstall

When you're done:

```bash
./stop.sh
```
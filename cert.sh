#!/bin/bash

CERT_DIR="./certs"
KEY_FILE="$CERT_DIR/server.key"
CRT_FILE="$CERT_DIR/server.crt"

mkdir -p "$CERT_DIR"

# Only generate if not already present
if [ ! -f "$KEY_FILE" ] || [ ! -f "$CRT_FILE" ]; then
    echo "Generating self-signed certificate..."

    openssl req -x509 -nodes -newkey rsa:4096 \
	    -keyout "$KEY_FILE" \
	    -out "$CRT_FILE" \
	    -days 365 \
	    -subj "/C=US/ST=GA/L=Athens/O=UGA/CN=localhost"

    echo "Certificate and key generated at:"
    echo " - $KEY_FILE"
    echo " - $CRT_FILE"
else
    echo "Certificate already exists. Skipping."
fi



#!/bin/bash

if [ -z "$1" ]; then
    echo "Usage: ./attach-client.sh <client-number>"
    exit 1
fi

CLIENT_ID=$1
CONTAINER_NAME="chat-client-$CLIENT_ID"

# Check if the container exists and is running
if ! sudo docker ps --format '{{.Names}}' | grep -q "^${CONTAINER_NAME}$"; then
    echo "Container ${CONTAINER_NAME} is not running."
    exit 1
fi

echo "Attaching to ${CONTAINER_NAME} and starting ./client ..."
sudo docker exec -it "$CONTAINER_NAME" bash -c "./client"

#!/bin/bash

# Command to run in each terminal
#CMD="./build/release/client"
CMD="/usr/bin/openssl s_client -connect 127.0.0.1:4400"

# Open 51 terminals, 51st should fail
for i in {1..51}
do
  gnome-terminal -- bash -c "$CMD"
done

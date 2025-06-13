CC = g++
CFLAGS = -std=c++11 -Wall -Wextra -O2
SERVER_SRC = udp_server.cpp
CLIENT_SRC = udp_client.cpp
SERVER_BIN = udp_server
CLIENT_BIN = udp_client

all: clean $(SERVER_BIN) $(CLIENT_BIN)

$(SERVER_BIN): $(SERVER_SRC)
	$(CC) $(CFLAGS) -o $(SERVER_BIN) $(SERVER_SRC)

$(CLIENT_BIN): $(CLIENT_SRC)
	$(CC) $(CFLAGS) -o $(CLIENT_BIN) $(CLIENT_SRC)

clean:
	rm -f $(SERVER_BIN) $(CLIENT_BIN)

.PHONY: all clean

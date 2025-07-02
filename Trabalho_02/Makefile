# Makefile for TCP File Transfer Project
# Compiler and flags
CXX = g++
CXXFLAGS = -std=c++11 -pthread -Wall -Wextra
LIBS = -lssl -lcrypto

# Target executables
SERVER = tcp_server
CLIENT = tcp_client

# Source files
SERVER_SRC = tcp_server.cpp
CLIENT_SRC = tcp_client.cpp

# Default target - build everything
all: clean $(SERVER) $(CLIENT)
	@echo "Build completed successfully!"
	@echo "Usage:"
	@echo "  Start server: ./$(SERVER)"
	@echo "  Start client: ./$(CLIENT) <IP> <port>"

# Build server
$(SERVER): $(SERVER_SRC)
	@echo "Compiling server..."
	$(CXX) $(CXXFLAGS) -o $(SERVER) $(SERVER_SRC) $(LIBS)
	@echo "Server compiled successfully!"

# Build client  
$(CLIENT): $(CLIENT_SRC)
	@echo "Compiling client..."
	$(CXX) $(CXXFLAGS) -o $(CLIENT) $(CLIENT_SRC) $(LIBS)
	@echo "Client compiled successfully!"

# Clean executables
clean:
	@echo "Cleaning previous builds..."
	@rm -f $(SERVER) $(CLIENT)
	@echo "Clean completed!"

# Install dependencies (Ubuntu/Debian)
install-deps:
	@echo "Installing OpenSSL development libraries..."
	sudo apt update
	sudo apt install libssl-dev

# Test compilation without linking
test:
	@echo "Testing compilation without linking..."
	$(CXX) $(CXXFLAGS) -c $(SERVER_SRC) -o server_test.o
	$(CXX) $(CXXFLAGS) -c $(CLIENT_SRC) -o client_test.o
	@rm -f server_test.o client_test.o
	@echo "Compilation test passed!"

# Debug build with extra information
debug: CXXFLAGS += -g -DDEBUG
debug: clean $(SERVER) $(CLIENT)
	@echo "Debug build completed!"

# Release build with optimizations
release: CXXFLAGS += -O2 -DNDEBUG
release: clean $(SERVER) $(CLIENT)
	@echo "Release build completed!"

# Check if OpenSSL is properly installed
check-deps:
	@echo "Checking OpenSSL installation..."
	@pkg-config --exists openssl && echo "OpenSSL found!" || echo "OpenSSL not found - run 'make install-deps'"
	@pkg-config --libs openssl 2>/dev/null || echo "OpenSSL libraries: -lssl -lcrypto"

# Help target
help:
	@echo "Available targets:"
	@echo "  all         - Clean and build both server and client (default)"
	@echo "  server      - Build only the server"
	@echo "  client      - Build only the client"
	@echo "  clean       - Remove compiled executables"
	@echo "  install-deps- Install OpenSSL development libraries"
	@echo "  test        - Test compilation without linking"
	@echo "  debug       - Build with debug symbols"
	@echo "  release     - Build with optimizations"
	@echo "  check-deps  - Check if OpenSSL is installed"
	@echo "  help        - Show this help message"

# Declare phony targets
.PHONY: all clean install-deps test debug release check-deps help
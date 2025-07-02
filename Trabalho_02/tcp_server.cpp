#include <iostream>
#include <string>
#include <vector>
#include <thread>
#include <mutex>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <cstring>
#include <unistd.h>
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <openssl/sha.h>
#include <signal.h>
#include <atomic>
#include <cstdint>
#include <chrono>

#define PORT 5555
#define BUFFER_SIZE 1024
#define MAX_CLIENTS 100

using namespace std;

class TCPServer {
private:
    int server_socket;
    vector<int> client_sockets;
    mutex client_mutex;
    mutex stdin_mutex;
    mutex log_mutex;  // Added for clean logging
    atomic<bool> stdin_occupied{false};
    atomic<bool> running{true};

public:
    TCPServer() : server_socket(-1) {
        signal(SIGPIPE, SIG_IGN);
    }

    ~TCPServer() {
        if (server_socket >= 0) {
            close(server_socket);
        }
    }

    string get_local_ip() {
        struct ifaddrs *ifaddr, *ifa;
        char ip[INET_ADDRSTRLEN];

        if (getifaddrs(&ifaddr) == -1) {
            perror("getifaddrs");
            return "127.0.0.1";
        }

        for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
            if (ifa->ifa_addr == NULL) continue;

            if (ifa->ifa_addr->sa_family == AF_INET) {
                struct sockaddr_in *sa = (struct sockaddr_in *)ifa->ifa_addr;
                inet_ntop(AF_INET, &(sa->sin_addr), ip, INET_ADDRSTRLEN);
                
                // Skip loopback, prefer eth0 or similar
                if (strcmp(ip, "127.0.0.1") != 0) {
                    freeifaddrs(ifaddr);
                    return string(ip);
                }
            }
        }

        freeifaddrs(ifaddr);
        return "127.0.0.1";
    }

    string calculate_sha256(const string& filename) {
        ifstream file(filename, ios::binary);
        if (!file) {
            return "ERROR";
        }

        SHA256_CTX sha256;
        SHA256_Init(&sha256);

        char buffer[BUFFER_SIZE];
        while (file.read(buffer, BUFFER_SIZE)) {
            SHA256_Update(&sha256, buffer, file.gcount());
        }
        
        if (file.gcount() > 0) {
            SHA256_Update(&sha256, buffer, file.gcount());
        }

        unsigned char hash[SHA256_DIGEST_LENGTH];
        SHA256_Final(hash, &sha256);

        stringstream ss;
        for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
            ss << hex << setw(2) << setfill('0') << static_cast<int>(hash[i]);
        }
        
        return ss.str();
    }

    void log_message(const string& message) {
        lock_guard<mutex> lock(log_mutex);
        cout << message << endl;
    }

    void broadcast_to_clients(const string& message) {
        lock_guard<mutex> lock(client_mutex);
        for (int client_sock : client_sockets) {
            send(client_sock, message.c_str(), message.length(), 0);
        }
    }

    void remove_client(int client_sock) {
        lock_guard<mutex> lock(client_mutex);
        client_sockets.erase(
            std::remove(client_sockets.begin(), client_sockets.end(), client_sock),
            client_sockets.end()
        );
    }

    void handle_client(int client_sock, sockaddr_in client_addr) {
        char ip_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(client_addr.sin_addr), ip_str, sizeof(ip_str));
        int port = ntohs(client_addr.sin_port);
        string client_id = string(ip_str) + ":" + to_string(port);

        log_message("\n=== [" + client_id + "] Client connected ===");

        char buffer[BUFFER_SIZE];
        ssize_t bytes;

        while ((bytes = recv(client_sock, buffer, BUFFER_SIZE - 1, 0)) > 0) {
            buffer[bytes] = '\0';
            string request(buffer);

            log_message("[" + client_id + "] Received: " + request);

            if (request == "FIN") {
                log_message("[" + client_id + "] Client disconnected");
                break;
            }
            else if (request.substr(0, 5) == "CHAT ") {
                string message = request.substr(5);
                log_message("[" + client_id + "] Chat: " + message);

                // Interactive chat response - completely stop other operations
                stdin_occupied = true;
                
                {
                    lock_guard<mutex> stdin_lock(stdin_mutex);
                    log_message("\n=== CHAT MODE: Respond to [" + client_id + "] ===");
                    log_message("Message: " + message);
                    
                    // Clear any leftover input
                    cin.clear();
                    
                    string response;
                    bool got_input = false;
                    
                    while (!got_input) {
                        cout << "\nYour response: (press enter and type) ";
                        cout.flush();
                        
                        if (getline(cin, response)) {
                            if (!response.empty()) {
                                got_input = true;
                            } else {
                                cout << "Please enter a non-empty response." << endl;
                            }
                        } else {
                            // If getline fails, clear and try again
                            cin.clear();
                            this_thread::sleep_for(chrono::milliseconds(1));
                        }
                    }

                    string full_response = response + "\n";
                    send(client_sock, full_response.c_str(), full_response.length(), 0);
                    log_message("Response sent: " + response);
                    log_message("=== END CHAT MODE ===\n");
                }
                
                stdin_occupied = false;
            }
            else if (request.substr(0, 4) == "GET ") {
                string filename = request.substr(4);
                log_message("[" + client_id + "] File request: " + filename);

                ifstream file(filename, ios::binary);
                if (!file) {
                    string error_msg = "ERROR: File not found\n";
                    send(client_sock, error_msg.c_str(), error_msg.length(), 0);
                    log_message("[" + client_id + "] File not found: " + filename);
                    continue;
                }

                // Calculate SHA-256 hash
                log_message("[" + client_id + "] Calculating SHA-256 hash...");
                string hash = calculate_sha256(filename);
                if (hash == "ERROR") {
                    string error_msg = "ERROR: Cannot calculate SHA-256 hash\n";
                    send(client_sock, error_msg.c_str(), error_msg.length(), 0);
                    continue;
                }
                log_message("[" + client_id + "] SHA-256: " + hash.substr(0, 16) + "...");

                // Send OK
                string ok_msg = "OK\n";
                send(client_sock, ok_msg.c_str(), ok_msg.length(), 0);

                // Get file size
                file.seekg(0, ios::end);
                long filesize = file.tellg();
                file.seekg(0, ios::beg);

                // Send file size
                string size_msg = "SIZE " + to_string(filesize) + "\n";
                send(client_sock, size_msg.c_str(), size_msg.length(), 0);
                log_message("[" + client_id + "] Sending file (" + to_string(filesize) + " bytes)");

                // Send file data with artificial delay
                char file_buffer[BUFFER_SIZE];
                long sent = 0;
                while (file.read(file_buffer, BUFFER_SIZE)) {
                    send(client_sock, file_buffer, file.gcount(), 0);
                    sent += file.gcount();
                    
                    // Artificial delay for large files to simulate network/processing time
                    if (filesize > 1024 * 1024) { // Files > 1MB
                        this_thread::sleep_for(chrono::milliseconds(1)); // 100ms per chunk
                    }
                    
                    // Progress log for large files
                    if (filesize > 5 * 1024 * 1024 && sent % (1024 * 1024) == 0) {
                        int progress = (sent * 100) / filesize;
                        log_message("[" + client_id + "] Transfer progress: " + to_string(progress) + "%");
                    }
                }
                
                // Send remaining bytes
                if (file.gcount() > 0) {
                    send(client_sock, file_buffer, file.gcount(), 0);
                }

                // Send hash
                string hash_msg = "HASH " + hash + "\n";
                send(client_sock, hash_msg.c_str(), hash_msg.length(), 0);

                log_message("[" + client_id + "] File and hash sent successfully");
            }
            else {
                log_message("[" + client_id + "] Unknown command: " + request);
            }
        }

        close(client_sock);
        remove_client(client_sock);
        log_message("[" + client_id + "] Connection closed");
    }

    void server_chat_thread() {
        string input;
        while (running) {
            // Only process server commands when not in chat mode
            if (stdin_occupied) {
                this_thread::sleep_for(chrono::milliseconds(200));
                continue;
            }

            cout << "[SERVER] > ";
            cout.flush();
            
            if (getline(cin, input)) {
                // Only process if we're not in chat mode
                if (stdin_occupied) {
                    continue;
                }
                
                if (input == "broadcast") {
                    stdin_occupied = true;
                    {
                        lock_guard<mutex> stdin_lock(stdin_mutex);
                        cout << "Enter message for all clients: ";
                        cout.flush();
                        
                        string message;
                        if (getline(cin, message) && !message.empty()) {
                            string full_msg = "[SERVER]: " + message + "\n";
                            broadcast_to_clients(full_msg);
                            log_message("Broadcast sent: " + message);
                        }
                    }
                    stdin_occupied = false;
                } else if (input == "quit") {
                    running = false;
                    break;
                } else if (input == "clients") {
                    lock_guard<mutex> lock(client_mutex);
                    log_message("Connected clients: " + to_string(client_sockets.size()));
                } else if (!input.empty()) {
                    cout << "Available commands: broadcast, clients, quit" << endl;
                }
            }
            
            // Prevent tight loop
            this_thread::sleep_for(chrono::milliseconds(50));
        }
    }

    void start() {
        server_socket = socket(AF_INET, SOCK_STREAM, 0);
        if (server_socket < 0) {
            perror("Error creating socket");
            return;
        }

        // Allow socket reuse
        int opt = 1;
        setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

        sockaddr_in server_addr{};
        server_addr.sin_family = AF_INET;
        server_addr.sin_addr.s_addr = INADDR_ANY;
        server_addr.sin_port = htons(PORT);

        if (bind(server_socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
            perror("Bind error");
            return;
        }

        if (listen(server_socket, 5) < 0) {
            perror("Listen error");
            return;
        }

        string ip = get_local_ip();
        cout << "=== TCP File Transfer Server ===" << endl;
        cout << "Server running on IP: " << ip << ":" << PORT << endl;
        cout << "Commands: broadcast, clients, quit" << endl;
        cout << "=================================" << endl;

        // Start server chat thread
        thread chat_thread(&TCPServer::server_chat_thread, this);
        chat_thread.detach();

        while (running) {
            sockaddr_in client_addr{};
            socklen_t client_len = sizeof(client_addr);

            int client_sock = accept(server_socket, (struct sockaddr *)&client_addr, &client_len);
            if (client_sock < 0) {
                if (running) {
                    perror("Accept error");
                }
                continue;
            }

            // Add client to list
            {
                lock_guard<mutex> lock(client_mutex);
                if (client_sockets.size() < MAX_CLIENTS) {
                    client_sockets.push_back(client_sock);
                }
            }

            // Create thread for client
            thread client_thread(&TCPServer::handle_client, this, client_sock, client_addr);
            client_thread.detach();
        }
    }
};

int main() {
    TCPServer server;
    server.start();
    return 0;
}
#include <iostream>
#include <string>
#include <thread>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <cstring>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <openssl/sha.h>
#include <atomic>
#include <chrono>

#define BUFFER_SIZE 1024

using namespace std;

class TCPClient {
private:
    int client_socket;
    atomic<bool> connected{false};
    atomic<bool> running{true};

public:
    TCPClient() : client_socket(-1) {}

    ~TCPClient() {
        if (client_socket >= 0) {
            close(client_socket);
        }
    }

    string calculate_sha256(const string& filename) {
        cout << "Calculating SHA-256 hash for received file..." << endl;
        
        ifstream file(filename, ios::binary);
        if (!file) {
            cerr << "Error opening file for SHA-256 calculation: " << filename << endl;
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

        cout << "SHA-256 calculation completed!" << endl;
        return ss.str();
    }

    string recv_line() {
        string line;
        char c;
        while (recv(client_socket, &c, 1, 0) > 0) {
            if (c == '\n') break;
            if (c != '\r') line += c;
        }
        return line;
    }

    void listen_server_thread() {
        char buffer[BUFFER_SIZE];
        while (connected && running) {
            ssize_t bytes = recv(client_socket, buffer, BUFFER_SIZE - 1, MSG_PEEK);
            if (bytes <= 0) {
                cout << "\n[SERVER DISCONNECTED]" << endl;
                connected = false;
                running = false;
                break;
            }

            buffer[bytes] = '\0';
            if (strncmp(buffer, "[SERVER]:", 9) == 0) {
                bytes = recv(client_socket, buffer, BUFFER_SIZE - 1, 0);
                buffer[bytes] = '\0';
                cout << "\n" << buffer << endl;
                cout << ">> ";
                cout.flush();
            } else {
                this_thread::sleep_for(chrono::milliseconds(1));
            }
        }
    }

    bool connect_to_server(const string& ip, int port) {
        client_socket = socket(AF_INET, SOCK_STREAM, 0);
        if (client_socket < 0) {
            perror("Error creating socket");
            return false;
        }

        sockaddr_in server_addr{};
        server_addr.sin_family = AF_INET;
        server_addr.sin_port = htons(port);
        
        if (inet_pton(AF_INET, ip.c_str(), &server_addr.sin_addr) <= 0) {
            cerr << "Invalid IP address: " << ip << endl;
            return false;
        }

        if (connect(client_socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
            perror("Connection error");
            return false;
        }

        connected = true;
        cout << "Connected to server " << ip << ":" << port << endl;
        return true;
    }

    void handle_file_request(const string& filename) {
        string output_filename = "received_" + filename;
        
        // Send GET request
        string request = "GET " + filename;
        send(client_socket, request.c_str(), request.length(), 0);

        // Receive response
        string response = recv_line();
        if (response.substr(0, 5) == "ERROR") {
            cout << response << endl;
            return;
        }

        if (response != "OK") {
            cout << "Invalid server response: " << response << endl;
            return;
        }

        // Receive file size
        string size_line = recv_line();
        if (size_line.substr(0, 5) != "SIZE ") {
            cout << "Invalid size response: " << size_line << endl;
            return;
        }

        long filesize = stol(size_line.substr(5));
        cout << "Receiving file: " << filename << " (" << filesize << " bytes)" << endl;

        // Create output file
        ofstream output(output_filename, ios::binary);
        if (!output) {
            perror("Error creating output file");
            return;
        }

        // Receive file data
        long received = 0;
        char file_buffer[BUFFER_SIZE];
        string remaining_data;
        
        while (received < filesize) {
            ssize_t bytes = recv(client_socket, file_buffer, BUFFER_SIZE, 0);
            if (bytes <= 0) {
                cout << "Error receiving file data" << endl;
                output.close();
                std::remove(output_filename.c_str());
                return;
            }

            size_t to_write = (received + bytes <= filesize) ? bytes : (filesize - received);
            output.write(file_buffer, to_write);
            received += to_write;

            // Save any extra data beyond file size (likely hash data)
            if (received == filesize && bytes > to_write) {
                size_t extra = bytes - to_write;
                remaining_data.assign(file_buffer + to_write, extra);
            }

            // Progress indicator
            if (filesize > 1024 * 1024) { // Show progress for files > 1MB
                int progress = (received * 100) / filesize;
                cout << "\rProgress: " << progress << "% (" << received << "/" << filesize << " bytes)";
                cout.flush();
            }
        }

        output.close();
        cout << "\nFile saved as: " << output_filename << endl;

        // Receive hash - check if we already have it in remaining_data
        string hash_line;
        if (!remaining_data.empty() && remaining_data.find("HASH ") != string::npos) {
            // Hash was received with file data
            hash_line = remaining_data;
            // Remove any trailing newlines or extra characters
            size_t hash_pos = hash_line.find("HASH ");
            if (hash_pos != string::npos) {
                hash_line = hash_line.substr(hash_pos);
                size_t newline_pos = hash_line.find('\n');
                if (newline_pos != string::npos) {
                    hash_line = hash_line.substr(0, newline_pos);
                }
            }
        } else {
            // Need to receive hash separately
            hash_line = recv_line();
        }

        if (hash_line.substr(0, 5) != "HASH ") {
            cout << "Invalid hash response: '" << hash_line << "'" << endl;
            return;
        }

        string server_hash = hash_line.substr(5);
        // Remove any trailing whitespace or newlines
        server_hash.erase(server_hash.find_last_not_of(" \t\r\n") + 1);
        
        cout << "Server hash: " << server_hash << endl;

        // Calculate local SHA-256 hash
        string local_hash = calculate_sha256(output_filename);
        cout << "Local hash : " << local_hash << endl;

        cout << "\nComparing hashes..." << endl;
        if (server_hash == local_hash) {
            cout << "File integrity verified successfully!" << endl;
            cout << "File transfer completed without corruption!" << endl;
        } else {
            cout << "File corrupted! Hashes do not match!" << endl;
            cout << "Removing corrupted file..." << endl;
            std::remove(output_filename.c_str());
        }
    }

    void handle_chat_request(const string& message) {
        string request = "CHAT " + message;
        send(client_socket, request.c_str(), request.length(), 0);
        cout << "You: " << message << endl;

        string response = recv_line();
        cout << "Server: " << response << endl;
    }

    void start_interactive_session() {
        // Start server listening thread
        thread listen_thread(&TCPClient::listen_server_thread, this);
        listen_thread.detach();

        cout << "\n=== TCP File Transfer Client ===" << endl;
        cout << "Commands:" << endl;
        cout << "  GET <filename>     - Download file" << endl;
        cout << "  CHAT <message>     - Send chat message" << endl;
        cout << "  FIN                - Disconnect" << endl;
        cout << "=================================" << endl;

        string input;
        while (connected && running) {
            cout << ">> ";
            if (!getline(cin, input)) {
                break;
            }

            if (input.empty()) continue;

            if (input == "FIN") {
                send(client_socket, input.c_str(), input.length(), 0);
                cout << "Disconnecting..." << endl;
                break;
            }
            else if (input.substr(0, 4) == "GET ") {
                string filename = input.substr(4);
                if (filename.empty()) {
                    cout << "Usage: GET <filename>" << endl;
                    continue;
                }
                handle_file_request(filename);
            }
            else if (input.substr(0, 5) == "CHAT ") {
                string message = input.substr(5);
                if (message.empty()) {
                    cout << "Usage: CHAT <message>" << endl;
                    continue;
                }
                handle_chat_request(message);
            }
            else {
                cout << "Unknown command. Available: GET, CHAT, FIN" << endl;
            }
        }

        connected = false;
        running = false;
    }
};

int main(int argc, char* argv[]) {
    if (argc != 3) {
        cerr << "Usage: " << argv[0] << " <IP> <Port>" << endl;
        return 1;
    }

    string ip = argv[1];
    int port = stoi(argv[2]);

    TCPClient client;
    if (!client.connect_to_server(ip, port)) {
        return 1;
    }

    client.start_interactive_session();
    return 0;
}
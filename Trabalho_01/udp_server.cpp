#include <iostream>
#include <cstring>
#include <unistd.h>
#include <arpa/inet.h>
#include <fstream>
#include <sys/socket.h>
#include <netinet/in.h>
#include <ifaddrs.h>
#include <sys/select.h>
#include <vector>
#include <cstdint>

#define PORT 4000
#define BUFFER_SIZE 1024
#define WINDOW_SIZE 5
#define HEADER_SIZE (sizeof(uint32_t) + sizeof(uint16_t) + sizeof(uint32_t))
#define DATA_SIZE (BUFFER_SIZE - HEADER_SIZE)
#define TIMEOUT_SEC 1
#define TIMEOUT_USEC 0

#define SYN_FLAG             0x01  // SYN flag to initiate connection
#define ACK_FLAG             0x02  // ACK flag to acknowledge connection
#define FIN_FLAG             0x03  // FIN flag to disconnect
#define GET_FLAG             0x04  // GET request flag
#define FILE_NOT_FOUND_FLAG  0x05  // File-not-found
#define OK_FLAG              0x06  // File-will-follow

using namespace std;

enum ServerState {
    WAITING_FOR_CONNECTION,
    CONNECTED
};

struct ClientSession {
    sockaddr_in addr;
    ServerState state;
    bool is_active;
    
    ClientSession() : state(WAITING_FOR_CONNECTION), is_active(false) {
        memset(&addr, 0, sizeof(addr));
    }
    
    bool matches(const sockaddr_in& client_addr) const {
        return (addr.sin_addr.s_addr == client_addr.sin_addr.s_addr && 
                addr.sin_port == client_addr.sin_port);
    }
};

struct Packet {
    uint32_t seq_num;     
    uint16_t size;        
    uint32_t checksum;    
    char data[DATA_SIZE]; 
    
    Packet() : seq_num(0), size(0), checksum(0) {
        memset(data, 0, DATA_SIZE);
    }
};

// Get the first non-loopback IPv4 address
string get_local_ip() {
    struct ifaddrs *ifs, *ifa;
    char buf[INET_ADDRSTRLEN];
    if (getifaddrs(&ifs) == -1) return "0.0.0.0";
    for (ifa = ifs; ifa; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr && ifa->ifa_addr->sa_family == AF_INET
            && strcmp(ifa->ifa_name, "lo") != 0) {
            auto *sin = (struct sockaddr_in*)ifa->ifa_addr;
            inet_ntop(AF_INET, &sin->sin_addr, buf, sizeof(buf));
            freeifaddrs(ifs);
            return string(buf);
        }
    }
    freeifaddrs(ifs);
    return "0.0.0.0";
}

// CRC32 checksum implementation
uint32_t crc32(const void *data, size_t n_bytes) {
    uint32_t crc = 0xFFFFFFFF;
    const uint8_t *bytes = (const uint8_t *)data;

    for (size_t i = 0; i < n_bytes; i++) {
        crc ^= bytes[i];
        for (int j = 0; j < 8; j++)
            crc = (crc >> 1) ^ (0xEDB88320 & -(crc & 1));
    }

    return ~crc;
}

void send_file_gobackn(int sockfd, const sockaddr_in &cli, const string &filename) {
    ifstream file(filename, ios::binary);
    if (!file) {
        uint8_t flag = FILE_NOT_FOUND_FLAG;
        sendto(sockfd, &flag, 1, 0, (sockaddr*)&cli, sizeof(cli));
        cout << "File not found: " << filename << endl;
        return;
    }

    // Get file size
    file.seekg(0, ios::end);
    size_t file_size = file.tellg();
    file.seekg(0, ios::beg);
    
    uint32_t total_packets = (file_size + DATA_SIZE - 1) / DATA_SIZE;
    cout << "File size: " << file_size << " bytes (" << total_packets << " packets)" << endl;

    // Send OK flag to indicate file will follow
    uint8_t ok_flag = OK_FLAG;
    sendto(sockfd, &ok_flag, 1, 0, (sockaddr*)&cli, sizeof(cli));
    cout << "Sending file: " << filename << " using Go-Back-N protocol" << endl;

    // Go-Back-N ARQ implementation
    vector<Packet> window(WINDOW_SIZE);
    uint32_t base = 0;
    uint32_t next_seq = 0;
    bool eof_reached = false;
    socklen_t len = sizeof(cli);
    uint32_t bytes_sent = 0;
    uint32_t retransmissions = 0;

    fd_set read_fds;
    struct timeval timeout;

    while (true) {
        // Send packets within window
        while (!eof_reached && next_seq < base + WINDOW_SIZE) {
            Packet &p = window[next_seq % WINDOW_SIZE];
            
            file.read(p.data, DATA_SIZE);
            size_t bytes_read = file.gcount();

            if (bytes_read == 0) {
                eof_reached = true;
                cout << "EOF reached. Total packets to send: " << next_seq << endl;
                break;
            }

            p.seq_num = next_seq;
            p.size = static_cast<uint16_t>(bytes_read);
            p.checksum = crc32(p.data, bytes_read);

            sendto(sockfd, &p, sizeof(Packet), 0, (sockaddr*)&cli, len);
            bytes_sent += bytes_read;
            
            cout << "Sent packet " << next_seq << " (" << bytes_read << " bytes) - Total: " 
                 << bytes_sent << "/" << file_size << " bytes (" 
                 << (bytes_sent * 100 / file_size) << "%)" << endl;

            next_seq++;
        }

        // Wait for ACK with timeout
        FD_ZERO(&read_fds);
        FD_SET(sockfd, &read_fds);
        timeout.tv_sec = TIMEOUT_SEC;
        timeout.tv_usec = TIMEOUT_USEC;

        int activity = select(sockfd + 1, &read_fds, NULL, NULL, &timeout);

        if (activity < 0) {
            perror("Select error");
            break;
        } else if (activity == 0) {
            // Timeout: retransmit all packets in window
            retransmissions++;
            cout << "TIMEOUT #" << retransmissions << "! Retransmitting window [" 
                 << base << "-" << (next_seq-1) << "]" << endl;
            
            for (uint32_t i = base; i < next_seq; ++i) {
                Packet &p = window[i % WINDOW_SIZE];
                sendto(sockfd, &p, sizeof(Packet), 0, (sockaddr*)&cli, len);
                cout << "  Retransmitted packet " << p.seq_num << endl;
            }
            
            // Check for too many retransmissions
            if (retransmissions > 10) {
                cout << "ERROR: Too many retransmissions (" << retransmissions 
                     << "). Client may have disconnected." << endl;
                break;
            }
        } else {
            // Receive ACK
            uint32_t ack;
            ssize_t ack_bytes = recvfrom(sockfd, &ack, sizeof(ack), 0, (sockaddr*)&cli, &len);
            if (ack_bytes < 0) {
                perror("Error receiving ACK");
                continue;
            }

            cout << "ACK received: " << ack << " (base was: " << base << ")" << endl;

            // Update base (cumulative ACK)
            if (ack >= base) {
                uint32_t old_base = base;
                base = ack + 1;
                cout << "Window advanced: [" << old_base << "->" << base << "]" << endl;
                retransmissions = 0; // Reset timeout counter on successful ACK
            } else {
                cout << "Old/duplicate ACK " << ack << " ignored (base=" << base << ")" << endl;
            }
        }

        // Stop condition: EOF + all packets acknowledged
        if (eof_reached && base >= next_seq) {
            cout << "SUCCESS: All " << next_seq << " packets sent and acknowledged!" << endl;
            cout << "File transfer completed: " << file_size << " bytes" << endl;
            break;
        }
        
        // Progress update
        if (base % 50 == 0 && base > 0) {
            uint32_t progress = (base * 100) / total_packets;
            cout << "Progress: " << base << "/" << total_packets << " packets (" << progress << "%)" << endl;
        }
    }

    file.close();
}

void start_server() {
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) { perror("socket"); return; }

    sockaddr_in serv{}, cli{};
    serv.sin_family = AF_INET;
    serv.sin_addr.s_addr = INADDR_ANY;
    serv.sin_port = htons(PORT);

    if (bind(sockfd, (sockaddr*)&serv, sizeof(serv)) < 0) {
        perror("bind"); close(sockfd); return;
    }

    string ip = get_local_ip();
    cout << "UDP server listening on IP " << ip << " port " << PORT << "...\n";

    ClientSession current_client;
    uint8_t buf[BUFFER_SIZE];
    socklen_t len = sizeof(cli);

    while (true) {
        int n = recvfrom(sockfd, buf, BUFFER_SIZE, 0, (sockaddr*)&cli, &len);
        if (n <= 0) continue;

        // Check if this is from the current connected client
        bool is_current_client = current_client.is_active && current_client.matches(cli);

        switch (current_client.state) {
            case WAITING_FOR_CONNECTION:
                if (buf[0] == SYN_FLAG) {
                    // Accept new connection
                    current_client.addr = cli;
                    current_client.state = CONNECTED;
                    current_client.is_active = true;
                    
                    uint8_t resp = ACK_FLAG;
                    sendto(sockfd, &resp, 1, 0, (sockaddr*)&cli, len);
                    
                    char client_ip[INET_ADDRSTRLEN];
                    inet_ntop(AF_INET, &cli.sin_addr, client_ip, INET_ADDRSTRLEN);
                    cout << "Connection established with client " << client_ip << ":" << ntohs(cli.sin_port) << endl;
                } else {
                    cout << "Ignoring non-SYN packet while waiting for connection" << endl;
                }
                break;

            case CONNECTED:
                if (!is_current_client) {
                    // Packet from different client while we have an active session
                    char other_ip[INET_ADDRSTRLEN];
                    inet_ntop(AF_INET, &cli.sin_addr, other_ip, INET_ADDRSTRLEN);
                    cout << "Ignoring packet from " << other_ip << ":" << ntohs(cli.sin_port) 
                         << " - already connected to another client" << endl;
                    
                    // Send busy response
                    uint8_t busy = FILE_NOT_FOUND_FLAG; // Reusing as "busy" signal
                    sendto(sockfd, &busy, 1, 0, (sockaddr*)&cli, len);
                    continue;
                }

                if (buf[0] == GET_FLAG) {
                    string fname((char*)buf + 1, n - 1);
                    cout << "GET request: " << fname << " from connected client" << endl;
                    send_file_gobackn(sockfd, cli, fname);
                }
                else if (buf[0] == FIN_FLAG) {
                    uint8_t resp = ACK_FLAG;
                    sendto(sockfd, &resp, 1, 0, (sockaddr*)&cli, len);
                    
                    char client_ip[INET_ADDRSTRLEN];
                    inet_ntop(AF_INET, &cli.sin_addr, client_ip, INET_ADDRSTRLEN);
                    cout << "Client " << client_ip << ":" << ntohs(cli.sin_port) << " disconnected." << endl;
                    
                    current_client.state = WAITING_FOR_CONNECTION;
                    current_client.is_active = false;
                }
                else {
                    cout << "Unknown command from connected client: " << int(buf[0]) << endl;
                }
                break;
        }
    }

    close(sockfd);
}

int main() {
    cout << "=== UDP File Transfer Server with Go-Back-N ARQ ===" << endl;
    cout << "Window Size: " << WINDOW_SIZE << " packets" << endl;
    cout << "Packet Size: " << DATA_SIZE << " bytes data + " << HEADER_SIZE << " bytes header" << endl;
    cout << "Timeout: " << TIMEOUT_SEC << " seconds" << endl;
    cout << "=================================================" << endl;
    
    start_server();
    return 0;
}
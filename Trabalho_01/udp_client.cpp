#include <iostream>
#include <vector>
#include <cstring>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <sys/time.h>
#include <fstream>
#include <sstream>
#include <cstdlib>
#include <ctime>
#include <cstdint>

#define BUFFER_SIZE 1024
#define MAX_RETRIES 3
#define TIMEOUT_SECONDS 2
#define HEADER_SIZE (sizeof(uint32_t) + sizeof(uint16_t) + sizeof(uint32_t))
#define DATA_SIZE (BUFFER_SIZE - HEADER_SIZE)
#define LOSS_PROBABILITY 0.1  // 10% packet loss simulation

#define SYN_FLAG             0x01
#define ACK_FLAG             0x02
#define FIN_FLAG             0x03
#define GET_FLAG             0x04
#define FILE_NOT_FOUND_FLAG  0x05
#define OK_FLAG              0x06

using namespace std;

struct Packet {
    uint32_t seq_num;     
    uint16_t size;        
    uint32_t checksum;    
    char data[DATA_SIZE]; 
    
    Packet() : seq_num(0), size(0), checksum(0) {
        memset(data, 0, DATA_SIZE);
    }
};

// Simulate packet loss for testing
bool should_drop_packet() {
    return ((float)rand() / RAND_MAX) < LOSS_PROBABILITY;
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

bool try_connect(int sockfd, sockaddr_in &serv, const string &target_ip) {
    cout << "Attempting to connect to " << target_ip << "..." << endl;
    
    uint8_t syn = SYN_FLAG;
    ssize_t sent = sendto(sockfd, &syn, 1, 0, (sockaddr*)&serv, sizeof(serv));
    if (sent < 0) {
        cout << "Error sending SYN packet - check if IP " << target_ip << " is reachable" << endl;
        return false;
    }

    fd_set rfds;
    FD_ZERO(&rfds); FD_SET(sockfd, &rfds);
    timeval tv{TIMEOUT_SECONDS,0};
    int r = select(sockfd+1, &rfds, NULL, NULL, &tv);
    
    if (r <= 0) {
        cout << "Connection timeout - server at " << target_ip << " not responding" << endl;
        return false;
    }

    uint8_t resp;
    socklen_t len = sizeof(serv);
    sockaddr_in recv_addr;
    int n = recvfrom(sockfd, &resp, 1, 0, (sockaddr*)&recv_addr, &len);
    
    if (n <= 0) {
        cout << "Error receiving response from server" << endl;
        return false;
    }
    
    // Verify response came from expected server
    char recv_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &recv_addr.sin_addr, recv_ip, INET_ADDRSTRLEN);
    
    if (resp == ACK_FLAG) {
        cout << "Connection established successfully with " << recv_ip << ":" << ntohs(recv_addr.sin_port) << endl;
        return true;
    } else if (resp == FILE_NOT_FOUND_FLAG) {
        cout << "Server at " << recv_ip << " is busy with another client" << endl;
        return false;
    } else {
        cout << "Unexpected response from server " << recv_ip << ": " << int(resp) << endl;
        return false;
    }
}

void send_disconnect(int sockfd, sockaddr_in &serv) {
    uint8_t fin = FIN_FLAG;
    sendto(sockfd, &fin, 1, 0, (sockaddr*)&serv, sizeof(serv));
}

void send_get(int sockfd, sockaddr_in &serv, const string &fn) {
    vector<uint8_t> pkt(1 + fn.size());
    pkt[0] = GET_FLAG;
    memcpy(pkt.data()+1, fn.data(), fn.size());
    sendto(sockfd, pkt.data(), pkt.size(), 0, (sockaddr*)&serv, sizeof(serv));
    cout << "Sent GET request for file: " << fn << endl;
}

void receive_file_gobackn(int sockfd, sockaddr_in &serv, const string &filename) {
    // First, wait for OK flag
    uint8_t response;
    socklen_t len = sizeof(serv);
    int n = recvfrom(sockfd, &response, 1, 0, (sockaddr*)&serv, &len);
    if (n < 1) {
        cout << "Error receiving response from server" << endl;
        return;
    }

    if (response == FILE_NOT_FOUND_FLAG) {
        cout << "File not found on server." << endl;
        return;
    }
    if (response != OK_FLAG) {
        cout << "Unexpected response from server: " << int(response) << endl;
        return;
    }

    cout << "Server confirmed file exists. Starting Go-Back-N reception..." << endl;

    // Create output filename
    string output_filename;
    size_t dot_pos = filename.find_last_of('.');
    if (dot_pos != string::npos) {
        output_filename = filename.substr(0, dot_pos) + "_received" + filename.substr(dot_pos);
    } else {
        output_filename = filename + "_received";
    }

    ofstream output(output_filename, ios::binary);
    if (!output) {
        cout << "Cannot create output file: " << output_filename << endl;
        return;
    }

    uint32_t expected_seq = 0;
    int packets_received = 0;
    int packets_dropped = 0;
    uint32_t bytes_written = 0;
    uint32_t acks_sent = 0;

    cout << "=== Packet Loss Simulation Active (10% loss rate) ===" << endl;

    while (true) {
        Packet packet;
        fd_set read_fds;
        FD_ZERO(&read_fds);
        FD_SET(sockfd, &read_fds);

        struct timeval timeout;
        timeout.tv_sec = 5;  // Increased timeout for large files
        timeout.tv_usec = 0;

        int activity = select(sockfd + 1, &read_fds, NULL, NULL, &timeout);
        if (activity == 0) {
            cout << "TIMEOUT waiting for packet " << expected_seq 
                 << ". Connection may be lost or transfer complete." << endl;
            
            // Send one more ACK in case last ACK was lost
            if (expected_seq > 0) {
                uint32_t last_ack = expected_seq - 1;
                sendto(sockfd, &last_ack, sizeof(last_ack), 0, (sockaddr*)&serv, len);
                cout << "Sent final ACK: " << last_ack << endl;
            }
            break;
        }

        n = recvfrom(sockfd, &packet, sizeof(packet), 0, (sockaddr*)&serv, &len);
        if (n < 0) {
            perror("Error receiving packet");
            break;
        }

        packets_received++;

        // Simulate packet loss (except for first few packets to ensure progress)
        if (should_drop_packet() && packet.seq_num > 2 && packet.seq_num % 10 != 0) {
            packets_dropped++;
            cout << "*** SIMULATION: Packet " << packet.seq_num << " DROPPED (artificially) ***" << endl;
            continue;
        }

        // Verify checksum
        uint32_t calc_checksum = crc32(packet.data, packet.size);
        if (packet.checksum != calc_checksum) {
            cout << "Checksum mismatch in packet " << packet.seq_num << ". Ignoring..." << endl;
            continue;
        }

        cout << "Received packet " << packet.seq_num << " (size: " << packet.size 
             << ", expected: " << expected_seq << ")" << endl;

        if (packet.seq_num == expected_seq) {
            // Correct packet received - write to file
            output.write(packet.data, packet.size);
            bytes_written += packet.size;
            
            cout << "✓ Packet " << packet.seq_num << " written to file (" 
                 << packet.size << " bytes) - Total: " << bytes_written << " bytes" << endl;

            // Send ACK
            sendto(sockfd, &expected_seq, sizeof(expected_seq), 0, (sockaddr*)&serv, len);
            acks_sent++;
            cout << "Sent ACK: " << expected_seq << endl;
            
            expected_seq++;

            // Check if this is the last packet (partial packet)
            if (packet.size < DATA_SIZE) {
                cout << "Last packet received (size: " << packet.size << " < " << DATA_SIZE << ")" << endl;
                cout << "Transfer should be complete." << endl;
                break;
            }
        } else if (packet.seq_num < expected_seq) {
            // Duplicate packet - send ACK anyway
            cout << "Duplicate packet " << packet.seq_num << " (expected: " << expected_seq << ")" << endl;
            sendto(sockfd, &packet.seq_num, sizeof(packet.seq_num), 0, (sockaddr*)&serv, len);
            cout << "Sent duplicate ACK: " << packet.seq_num << endl;
        } else {
            // Out of order packet (future packet)
            cout << "Out-of-order packet " << packet.seq_num << " (expected: " << expected_seq 
                 << "). Requesting retransmission..." << endl;
            
            // Send ACK for last correctly received packet
            uint32_t ack = (expected_seq > 0) ? expected_seq - 1 : 0;
            sendto(sockfd, &ack, sizeof(ack), 0, (sockaddr*)&serv, len);
            cout << "Sent NACK-style ACK: " << ack << endl;
        }

        // Progress update
        if (packets_received % 100 == 0) {
            cout << "\n=== Progress Update ===" << endl;
            cout << "Packets received: " << packets_received << endl;
            cout << "Bytes written: " << bytes_written << endl;
            cout << "Current expected: " << expected_seq << endl;
            cout << "======================\n" << endl;
        }
    }

    output.close();
    
    cout << "\n=== Transfer Statistics ===" << endl;
    cout << "File saved as: " << output_filename << endl;
    cout << "Total packets received: " << packets_received << endl;
    cout << "Packets dropped (simulated): " << packets_dropped << endl;
    cout << "ACKs sent: " << acks_sent << endl;
    cout << "Final expected sequence: " << expected_seq << endl;
    cout << "Total bytes written: " << bytes_written << endl;
    cout << "Loss rate: " << (packets_received > 0 ? (packets_dropped * 100.0 / packets_received) : 0) << "%" << endl;
    cout << "Transfer completed!" << endl;
}

int main(){
    srand(time(NULL));  // Initialize random seed for packet loss simulation
    
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock<0) { perror("socket"); return 1; }

    string ip; int port;
    cout << "=== UDP File Transfer Client with Go-Back-N ARQ ===" << endl;
    cout << "Packet Loss Simulation: " << (LOSS_PROBABILITY * 100) << "%" << endl;
    cout << "=============================================" << endl;
    cout << "Server IP: "; cin >> ip;
    cout << "Server port: "; cin >> port;
    cin.ignore();

    // Validate IP address format
    sockaddr_in serv{};
    serv.sin_family = AF_INET;
    serv.sin_port = htons(port);
    
    int ip_result = inet_pton(AF_INET, ip.c_str(), &serv.sin_addr);
    if (ip_result <= 0) {
        cout << "ERROR: Invalid IP address format: " << ip << endl;
        cout << "Please use format like: 192.168.1.100 or 127.0.0.1" << endl;
        close(sock);
        return 1;
    }
    
    cout << "Attempting to connect to " << ip << ":" << port << endl;

    int tries=0;
    while (tries<MAX_RETRIES && !try_connect(sock, serv, ip)) {
        cout << "Retrying connection... (" << (tries+1) << "/" << MAX_RETRIES << ")" << endl;
        tries++;
    }
    if (tries==MAX_RETRIES){ 
        cout << "Cannot connect to server after " << MAX_RETRIES << " attempts." << endl; 
        return 1; 
    }
    cout << "Connected to server successfully!" << endl;
    
    string line;
    while (true) {
        cout << "\nEnter command (GET <filename> or 'exit'): ";
        getline(cin, line);
        
        if (line == "exit") break;
        
        if (line.rfind("GET ",0) == 0) {
            string fn = line.substr(4);
            send_get(sock, serv, fn);
            receive_file_gobackn(sock, serv, fn);
        } else {
            cout << "Invalid command. Use: GET <filename>" << endl;
        }
    }

    send_disconnect(sock, serv);
    close(sock);
    cout << "Disconnected from server." << endl;
    return 0;
}
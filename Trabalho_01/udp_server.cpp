#include <iostream>
#include <cstring>
#include <unistd.h>
#include <arpa/inet.h>
#include <fstream>
#include <sys/socket.h>
#include <netinet/in.h>
#include <ifaddrs.h>

#define PORT 4000
#define BUFFER_SIZE 1024

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

void send_file(int sockfd, const sockaddr_in &cli, const string &filename) {
    ifstream file(filename, ios::binary);
    if (!file) {
        uint8_t flag = FILE_NOT_FOUND_FLAG;
        sendto(sockfd, &flag, 1, 0, (sockaddr*)&cli, sizeof(cli));
        cout << "File not found: " << filename << endl;
        return;
    }

    // determine file size
    file.seekg(0, ios::end);
    uint32_t fsize = file.tellg();
    file.seekg(0, ios::beg);

    // send header: [ OK_FLAG | 4-byte length ]
    uint8_t header[5];
    header[0] = OK_FLAG;
    uint32_t nbo = htonl(fsize);
    memcpy(header + 1, &nbo, 4);
    sendto(sockfd, header, sizeof(header), 0, (sockaddr*)&cli, sizeof(cli));

    // stream file data
    char buf[BUFFER_SIZE];
    while (file.read(buf, sizeof(buf))) {
        sendto(sockfd, buf, file.gcount(), 0, (sockaddr*)&cli, sizeof(cli));
    }
    if (file.gcount() > 0) {
        sendto(sockfd, buf, file.gcount(), 0, (sockaddr*)&cli, sizeof(cli));
    }
    cout << "File sent: " << filename << " (" << fsize << " bytes)" << endl;
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

    ServerState state = WAITING_FOR_CONNECTION;
    uint8_t buf[BUFFER_SIZE];
    socklen_t len = sizeof(cli);

    while (true) {
        int n = recvfrom(sockfd, buf, BUFFER_SIZE, 0, (sockaddr*)&cli, &len);
        if (n <= 0) continue;

        switch (state) {
            case WAITING_FOR_CONNECTION:
                if (buf[0] == SYN_FLAG) {
                    uint8_t resp = ACK_FLAG;
                    sendto(sockfd, &resp, 1, 0, (sockaddr*)&cli, len);
                    state = CONNECTED;
                    cout << "Connection established.\n";
                }
                break;

            case CONNECTED:
                if (buf[0] == GET_FLAG) {
                    string fname((char*)buf + 1, n - 1);
                    cout << "GET request: " << fname << endl;
                    send_file(sockfd, cli, fname);
                }
                else if (buf[0] == FIN_FLAG) {
                    uint8_t resp = ACK_FLAG;
                    sendto(sockfd, &resp, 1, 0, (sockaddr*)&cli, len);
                    state = WAITING_FOR_CONNECTION;
                    cout << "Client disconnected.\n";
                }
                break;
        }
    }
}

int main() {
    start_server();
    return 0;
}

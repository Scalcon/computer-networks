#include <iostream>
#include <vector>           // <— added
#include <cstring>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <sys/time.h>
#include <fstream>
#include <sstream>

#define BUFFER_SIZE 1024
#define MAX_RETRIES 3
#define TIMEOUT_SECONDS 2

#define SYN_FLAG             0x01
#define ACK_FLAG             0x02
#define FIN_FLAG             0x03
#define GET_FLAG             0x04
#define FILE_NOT_FOUND_FLAG  0x05
#define OK_FLAG              0x06

using namespace std;

bool try_connect(int sockfd, sockaddr_in &serv) {
    uint8_t syn = SYN_FLAG;
    sendto(sockfd, &syn, 1, 0, (sockaddr*)&serv, sizeof(serv));

    fd_set rfds;
    FD_ZERO(&rfds); FD_SET(sockfd, &rfds);
    timeval tv{TIMEOUT_SECONDS,0};
    int r = select(sockfd+1, &rfds, NULL, NULL, &tv);
    if (r <= 0) return false;

    uint8_t resp;
    socklen_t len = sizeof(serv);
    int n = recvfrom(sockfd, &resp, 1, 0, (sockaddr*)&serv, &len);
    return (n>0 && resp==ACK_FLAG);
}

void send_disconnect(int sockfd, sockaddr_in &serv) {
    uint8_t fin = FIN_FLAG;
    sendto(sockfd, &fin, 1, 0, (sockaddr*)&serv, sizeof(serv));
}

void send_get(int sockfd, sockaddr_in &serv, const string &fn) {
    // build packet: [ GET_FLAG | filename bytes ]
    std::vector<uint8_t> pkt(1 + fn.size());
    pkt[0] = GET_FLAG;
    memcpy(pkt.data()+1, fn.data(), fn.size());
    sendto(sockfd, pkt.data(), pkt.size(), 0, (sockaddr*)&serv, sizeof(serv));
    cout << "Sent GET request for file: " << fn << endl;
}

void receive_file(int sockfd, sockaddr_in &serv, const string &outname) {
    uint8_t header[5];
    socklen_t len = sizeof(serv);
    int n = recvfrom(sockfd, header, 5, 0, (sockaddr*)&serv, &len);
    if (n < 1) { cout<<"Error receiving header\n"; return; }

    if (header[0]==FILE_NOT_FOUND_FLAG) {
        cout<<"File not found on server.\n";
        return;
    }
    if (header[0]!=OK_FLAG) {
        cout<<"Unexpected flag "<<int(header[0])<<"\n";
        return;
    }

    uint32_t fsize;
    memcpy(&fsize, header+1, 4);
    fsize = ntohl(fsize);

    ofstream out(outname, ios::binary);
    if (!out) { cout<<"Cannot open "<<outname<<"\n"; return; }

    uint32_t got = 0;
    while (got < fsize) {
        uint8_t buf[BUFFER_SIZE];
        int toread = min<uint32_t>(BUFFER_SIZE, fsize - got);
        n = recvfrom(sockfd, buf, toread, 0, (sockaddr*)&serv, &len);
        if (n <= 0) { cout<<"Transfer error\n"; return; }
        out.write((char*)buf, n);
        got += n;
    }

    cout<<"File "<<outname<<" ("<<fsize<<" bytes) received.\n";
}

int main(){
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock<0) { perror("socket"); return 1; }

    string ip; int port;
    cout<<"Server IP: "; cin>>ip;
    cout<<"Server port: "; cin>>port;
    cin.ignore();

    sockaddr_in serv{};
    serv.sin_family = AF_INET;
    serv.sin_port = htons(port);
    inet_pton(AF_INET, ip.c_str(), &serv.sin_addr);

    int tries=0;
    while (tries<MAX_RETRIES && !try_connect(sock, serv)) {
        cout<<"Retrying connection...\n";
        tries++;
    }
    if (tries==MAX_RETRIES){ cout<<"Cannot connect\n"; return 1; }
    cout<<"Connected.\n";
    string line;
    while (true) {
        cout<<"GET filename or exit: ";
        getline(cin, line);
        if (line=="exit") break;
        if (line.rfind("GET ",0)==0) {
            string fn = line.substr(4);
            send_get(sock, serv, fn);
            receive_file(sock, serv, "received_"+fn);
        } else {
            cout<<"Invalid format\n";
        }
    }

    send_disconnect(sock, serv);
    close(sock);
    return 0;
}

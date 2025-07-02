#include <iostream>
#include <string>
#include <vector> // Mantido para 'vector<int> client_sockets' mas será esvaziado, ou pode ser removido se não houver uso.
#include <thread>
#include <mutex>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <algorithm> // Para std::transform
#include <cstring>
#include <unistd.h>    // Para close()
#include <arpa/inet.h> // Para inet_ntop
#include <ifaddrs.h>   // Para getifaddrs
#include <netinet/in.h> // Para sockaddr_in
#include <sys/socket.h> // Para socket(), bind(), listen(), accept()
#include <signal.h>    // Para signal()
#include <atomic>      // Para atomic<bool>
#include <cstdint>     // Para int64_t, etc.
#include <chrono>      // Para std::chrono::milliseconds

#define PORT 5555 // Porta para escutar, maior que 1024
#define BUFFER_SIZE 4096 // Aumentado para lidar melhor com dados de arquivos
#define MAX_CLIENTS 100 // Capacidade máxima de clientes, embora não gerenciado explicitamente por uma lista agora.

using namespace std;

// Funções utilitárias para HTTP
string get_content_type(const string& filename) {
    size_t dot_pos = filename.find_last_of('.');
    if (dot_pos == string::npos) {
        return "application/octet-stream"; // Tipo genérico se não tiver extensão
    }
    string ext = filename.substr(dot_pos + 1);
    transform(ext.begin(), ext.end(), ext.begin(), ::tolower); // Converte para minúsculas

    // Mapeamento de extensões para Content-Type
    if (ext == "html" || ext == "htm") return "text/html"; //
    if (ext == "jpeg" || ext == "jpg") return "image/jpeg"; //
    if (ext == "png") return "image/png";
    if (ext == "gif") return "image/gif";
    if (ext == "css") return "text/css";
    if (ext == "js") return "application/javascript";
    if (ext == "json") return "application/json";
    if (ext == "pdf") return "application/pdf";
    if (ext == "txt") return "text/plain";
    return "application/octet-stream"; // Padrão
}

class TCPServer {
private:
    int server_socket;
    // Removido client_sockets, client_mutex pois não há mais broadcast ou lista explícita de clientes.
    // O controle de clientes é feito pelas threads individuais.
    mutex log_mutex;  // Para log limpo
    atomic<bool> running{true}; // Para controlar o loop principal do servidor e a thread de chat.

public:
    TCPServer() : server_socket(-1) {
        signal(SIGPIPE, SIG_IGN); // Ignora SIGPIPE para evitar crash se um cliente fechar a conexão inesperadamente
    }

    ~TCPServer() {
        if (server_socket >= 0) {
            close(server_socket); // Fecha o socket do servidor ao destruir o objeto
        }
    }

    // Função para obter o IP local do servidor
    string get_local_ip() {
        struct ifaddrs *ifaddr, *ifa;
        char ip[INET_ADDRSTRLEN];

        if (getifaddrs(&ifaddr) == -1) {
            perror("getifaddrs");
            return "127.0.0.1";
        }

        for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
            if (ifa->ifa_addr == NULL) continue;

            // Para endereços IPv4
            if (ifa->ifa_addr->sa_family == AF_INET) {
                struct sockaddr_in *sa = (struct sockaddr_in *)ifa->ifa_addr;
                inet_ntop(AF_INET, &(sa->sin_addr), ip, INET_ADDRSTRLEN);
                
                // Prioriza IPs que não sejam de loopback e não sejam a interface 'lo'
                if (strcmp(ip, "127.0.0.1") != 0 && strcmp(ifa->ifa_name, "lo") != 0) {
                    freeifaddrs(ifaddr);
                    return string(ip);
                }
            }
        }
        freeifaddrs(ifaddr);
        return "127.0.0.1"; // Retorna loopback se nenhum outro IP válido for encontrado
    }

    // Função para logar mensagens de forma segura entre threads
    void log_message(const string& message) {
        lock_guard<mutex> lock(log_mutex);
        cout << message << endl;
    }

    // Função para enviar uma resposta HTTP de erro (404 Not Found)
    void send_http_error(int client_sock, const string& client_id, const string& error_message) {
        string response = "HTTP/1.0 404 Not Found\r\n"; //
        response += "Content-Type: text/html\r\n"; //
        response += "Connection: close\r\n"; //
        response += "\r\n"; // Linha vazia para separar cabeçalhos do corpo HTTP
        response += "<!DOCTYPE html><html><head><title>404 Not Found</title></head><body>"; //
        response += "<h1>404 Not Found</h1>"; //
        response += "<p>" + error_message + "</p>"; //
        response += "</body></html>"; //
        
        send(client_sock, response.c_str(), response.length(), 0);
        log_message("[" + client_id + "] Enviou 404 Not Found: " + error_message); //
    }

    // Função para lidar com cada cliente conectado em uma thread separada
    void handle_client(int client_sock, sockaddr_in client_addr) {
        char ip_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(client_addr.sin_addr), ip_str, sizeof(ip_str));
        int port = ntohs(client_addr.sin_port);
        string client_id = string(ip_str) + ":" + to_string(port);

        log_message("\n=== [" + client_id + "] Cliente conectado ===");

        char buffer[BUFFER_SIZE];
        ssize_t bytes_received;

        // Define um timeout para o recebimento de dados para evitar que a thread fique presa
        struct timeval timeout;
        timeout.tv_sec = 5; // 5 segundos
        timeout.tv_usec = 0;
        setsockopt(client_sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof timeout);

        string received_data;
        bool header_received = false;

        // Loop para receber dados até encontrar a sequência de fim de cabeçalhos HTTP
        while ((bytes_received = recv(client_sock, buffer, BUFFER_SIZE - 1, 0)) > 0) {
            buffer[bytes_received] = '\0';
            received_data += buffer;

            // Verifica se a requisição HTTP completa foi recebida (incluindo a linha vazia "\r\n\r\n")
            if (received_data.find("\r\n\r\n") != string::npos) {
                header_received = true;
                break;
            }
        }

        if (!header_received) {
            log_message("[" + client_id + "] Erro: Requisição HTTP incompleta ou tempo limite.");
            send_http_error(client_sock, client_id, "Bad Request or Timeout"); //
            close(client_sock); // Fecha o socket do cliente
            return; // Termina a thread do cliente
        }

        // Parse da primeira linha da requisição HTTP (ex: GET /pagina.html HTTP/1.0)
        stringstream ss(received_data);
        string request_line;
        getline(ss, request_line); // Pega a primeira linha da requisição

        log_message("[" + client_id + "] Requisição HTTP: " + request_line);

        string method, path, http_version;
        stringstream req_ss(request_line);
        req_ss >> method >> path >> http_version;

        if (method != "GET") { // O servidor deve tratar requisições GET
            log_message("[" + client_id + "] Método HTTP não suportado: " + method);
            send_http_error(client_sock, client_id, "Method Not Allowed"); // Retorna erro se o método não for GET
            close(client_sock);
            return;
        }

        // Trata a requisição da raiz ("/") para index.html, conforme padrão HTTP
        if (path == "/") {
            path = "/index.html";
        }

        // Remove o '/' inicial para obter o nome do arquivo
        string filename = path.substr(1); 
        
        // Remove quaisquer parâmetros de consulta (ex: /file.html?param=value)
        size_t query_pos = filename.find('?');
        if (query_pos != string::npos) {
            filename = filename.substr(0, query_pos);
        }

        log_message("[" + client_id + "] Arquivo solicitado: " + filename);

        // Abre o arquivo em modo binário e posiciona no final para obter o tamanho
        ifstream file(filename, ios::binary | ios::ate); 
        if (!file) {
            log_message("[" + client_id + "] Erro: Arquivo não encontrado - " + filename);
            send_http_error(client_sock, client_id, "File '" + filename + "' not found"); // Retorna 404 se o arquivo não existir
            close(client_sock);
            return;
        }

        long filesize = file.tellg(); // Obtém o tamanho do arquivo
        file.seekg(0, ios::beg);     // Volta para o início do arquivo

        string content_type = get_content_type(filename); // Determina o Content-Type

        // Constrói a resposta HTTP 200 OK
        stringstream http_response;
        http_response << "HTTP/1.0 200 OK\r\n"; // Status line
        http_response << "Content-Type: " << content_type << "\r\n"; // Tipo de conteúdo
        http_response << "Content-Length: " << filesize << "\r\n"; // Tamanho do conteúdo
        http_response << "Connection: close\r\n"; // Indica que a conexão será fechada após a resposta
        http_response << "\r\n"; // Fim dos cabeçalhos HTTP

        string response_header = http_response.str();
        send(client_sock, response_header.c_str(), response_header.length(), 0); // Envia os cabeçalhos
        log_message("[" + client_id + "] Enviando cabeçalhos HTTP para " + filename + " (Tamanho: " + to_string(filesize) + " bytes, Tipo: " + content_type + ")");

        // Envia o conteúdo do arquivo em chunks
        char file_buffer[BUFFER_SIZE];
        while (file.read(file_buffer, BUFFER_SIZE)) {
            send(client_sock, file_buffer, file.gcount(), 0);
        }
        if (file.gcount() > 0) { // Envia os bytes restantes, se houver
            send(client_sock, file_buffer, file.gcount(), 0);
        }
        file.close(); // Fecha o arquivo

        log_message("[" + client_id + "] Arquivo enviado com sucesso.");

        close(client_sock); // Fecha o socket do cliente
        log_message("[" + client_id + "] Conexão encerrada.");
    }

    // A thread de chat do servidor simplificada, apenas para "quit"
    void server_chat_thread() {
        string input;
        while (running) {
            cout << "[SERVIDOR] > ";
            cout.flush();
            
            // Lê a entrada do console
            if (getline(cin, input)) {
                if (input == "quit") {
                    log_message("Encerrando servidor...");
                    running = false; // Sinaliza para o loop principal parar
                    // Fecha o socket de escuta para desbloquear o accept()
                    shutdown(server_socket, SHUT_RDWR); 
                    break;
                } else if (!input.empty()) {
                    cout << "Comandos disponíveis: quit" << endl; // Apenas o comando quit é relevante agora.
                }
            } else {
                 // Limpa o estado de erro do cin se EOF ou falha, e espera um pouco.
                cin.clear();
                this_thread::sleep_for(chrono::milliseconds(50));
            }
        }
    }

    void start() {
        server_socket = socket(AF_INET, SOCK_STREAM, 0); // Cria o socket TCP
        if (server_socket < 0) {
            perror("Erro ao criar socket");
            return;
        }

        // Permite a reutilização do endereço e porta, útil para testes rápidos
        int opt = 1;
        setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

        sockaddr_in server_addr{};
        server_addr.sin_family = AF_INET;
        server_addr.sin_addr.s_addr = INADDR_ANY; // Escuta em todas as interfaces de rede
        server_addr.sin_port = htons(PORT); // Converte a porta para network byte order

        if (bind(server_socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
            perror("Erro no bind");
            close(server_socket);
            return;
        }

        if (listen(server_socket, 10) < 0) { // Começa a escutar por conexões, com backlog de 10
            perror("Erro no listen");
            close(server_socket);
            return;
        }

        string ip = get_local_ip();
        cout << "=== Servidor HTTP Simplificado ===" << endl;
        cout << "Servidor rodando no IP: " << ip << ":" << PORT << endl; // Mostra IP e Porta
        cout << "Comandos de servidor: quit" << endl; // Apenas 'quit' agora.
        cout << "=================================" << endl;

        // Inicia a thread para comandos do servidor (apenas 'quit' agora)
        thread chat_thread(&TCPServer::server_chat_thread, this);
        chat_thread.detach(); // Desvincula a thread; ela rodará independentemente

        // Loop principal para aceitar novas conexões de clientes
        while (running) {
            sockaddr_in client_addr{};
            socklen_t client_len = sizeof(client_addr);

            int client_sock = accept(server_socket, (struct sockaddr *)&client_addr, &client_len); // Aceita uma nova conexão
            if (client_sock < 0) {
                if (running) { // Se o servidor ainda estiver rodando, é um erro real. Se não, é porque o quit() fechou o socket.
                    perror("Erro no accept");
                }
                continue;
            }

            // Não há mais gerenciamento explícito de MAX_CLIENTS por uma lista,
            // mas o sistema operacional ainda pode limitar o número de conexões ativas.
            // Cria uma nova thread para lidar com o cliente recém-conectado
            thread client_thread(&TCPServer::handle_client, this, client_sock, client_addr);
            client_thread.detach(); // Desvincula a thread
        }
        
        log_message("Servidor encerrado.");
    }
};

int main() {
    TCPServer server;
    server.start();
    return 0;
}
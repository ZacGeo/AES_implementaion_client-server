#include <iostream>
#include <cstring>
#include <cstdint>
#include <ctime>
#include <string>
#include <iomanip>
#include <sstream>
#include <thread>           // ← ADD THIS
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>

// ============================================================
//  HACKER SNIFFER — MAN-IN-THE-MIDDLE TCP PROXY
//  Sits between client and server, reads ALL traffic in both
//  directions. Before AES: sees plaintext messages.
//  After AES: sees only binary gibberish.
// ============================================================

#define RED     "\033[1;31m"
#define GREEN   "\033[1;32m"
#define YELLOW  "\033[1;33m"
#define CYAN    "\033[1;36m"
#define MAGENTA "\033[1;35m"
#define RESET   "\033[0m"
#define BOLD    "\033[1m"

const char* REAL_SERVER_IP   = "127.0.0.1";
const int   REAL_SERVER_PORT = 8080;
const int   SNIFFER_PORT     = 8081;

std::string timestamp() {
    time_t now = time(nullptr);
    char buf[20];
    strftime(buf, sizeof(buf), "%H:%M:%S", localtime(&now));
    return std::string(buf);
}

std::string hexDump(const std::string& data) {
    std::ostringstream oss;
    for (size_t i = 0; i < data.size(); i++) {
        oss << std::hex << std::setw(2) << std::setfill('0')
            << (static_cast<unsigned int>(
                    static_cast<unsigned char>(data[i])))
            << " ";
        if ((i + 1) % 16 == 0) oss << "\n           ";
    }
    return oss.str();
}

bool isPrintable(const std::string& data) {
    for (unsigned char c : data) {
        if (c < 0x20 && c != '\n' && c != '\r' && c != '\t')
            return false;
        if (c > 0x7E) return false;
    }
    return true;
}

bool recvAll(int sock, void* data, size_t len) {
    char* ptr = static_cast<char*>(data);
    while (len > 0) {
        ssize_t received = recv(sock, ptr, len, 0);
        if (received <= 0) return false;
        ptr += received;
        len -= received;
    }
    return true;
}

bool sendAll(int sock, const void* data, size_t len) {
    const char* ptr = static_cast<const char*>(data);
    while (len > 0) {
        ssize_t sent = send(sock, ptr, len, 0);
        if (sent <= 0) return false;
        ptr += sent;
        len -= sent;
    }
    return true;
}

// ── Intercept one framed message, log it, forward it ─────────
bool interceptMessage(int fromSock, int toSock,
                      const std::string& direction,
                      const char* color,
                      const std::string& label) {

    uint32_t netLen = 0;
    if (!recvAll(fromSock, &netLen, 4)) return false;

    uint32_t msgLen = ntohl(netLen);

    if (msgLen == 0 || msgLen > 65536) {
        std::cout << RED << "[!] Suspicious length: "
                  << msgLen << RESET << "\n";
        return false;
    }

    std::string payload(msgLen, '\0');
    if (!recvAll(fromSock, &payload[0], msgLen)) return false;

    // Log the intercepted message
    std::cout << "\n" << BOLD << color
              << "┌─ [" << timestamp() << "] "
              << direction << " ──────────────────────────\n"
              << "│  " << label << "\n"
              << "│  Size   : " << msgLen << " bytes\n";

    if (isPrintable(payload)) {
        std::cout << "│  Content: " << GREEN << payload << color << "\n"
                  << "│  Status : " << YELLOW
                  << "⚠  PLAINTEXT — hacker can read this!" << color << "\n";
    } else {
        std::cout << "│  Content: [BINARY DATA — not printable]\n"
                  << "│  Hex    : " << hexDump(payload) << "\n"
                  << "│  Status : " << GREEN
                  << "✓  ENCRYPTED — hacker sees only gibberish." << color << "\n";
    }

    std::cout << "└───────────────────────────────────────────────────\n"
              << RESET << std::flush;

    // Forward unchanged to real destination
    if (!sendAll(toSock, &netLen, 4))            return false;
    if (!sendAll(toSock, payload.data(), msgLen)) return false;

    return true;
}

// ── Handle one client connection ──────────────────────────────
void handleConnection(int clientSock, int clientNum) {

    // Connect to real server
    int serverSock = socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in serverAddr;
    serverAddr.sin_family      = AF_INET;
    serverAddr.sin_port        = htons(REAL_SERVER_PORT);
    inet_pton(AF_INET, REAL_SERVER_IP, &serverAddr.sin_addr);

    if (connect(serverSock,
                reinterpret_cast<sockaddr*>(&serverAddr),
                sizeof(serverAddr)) < 0) {
        std::cout << RED << "[!] Cannot reach real server.\n" << RESET;
        close(clientSock);
        return;
    }

    std::cout << CYAN << BOLD
              << "\n[+] Client " << clientNum
              << " connected. Proxying to server...\n" << RESET;

    // Relay loop — watch both sockets simultaneously
    while (true) {
        fd_set readSet;
        FD_ZERO(&readSet);
        FD_SET(clientSock, &readSet);
        FD_SET(serverSock, &readSet);
        int maxFd = std::max(clientSock, serverSock) + 1;

        int ready = select(maxFd, &readSet, nullptr, nullptr, nullptr);
        if (ready <= 0) break;

        // Client → Server
        if (FD_ISSET(clientSock, &readSet)) {
            std::string dir = "CLIENT " + std::to_string(clientNum)
                              + " → SERVER";
            std::string lbl = "Client " + std::to_string(clientNum)
                              + " sending to server";
            if (!interceptMessage(clientSock, serverSock,
                                  dir, MAGENTA, lbl)) {
                std::cout << YELLOW << "[!] Client "
                          << clientNum << " disconnected.\n" << RESET;
                break;
            }
        }

        // Server → Client
        if (FD_ISSET(serverSock, &readSet)) {
            std::string dir = "SERVER → CLIENT "
                              + std::to_string(clientNum);
            std::string lbl = "Server sending to client "
                              + std::to_string(clientNum);
            if (!interceptMessage(serverSock, clientSock,
                                  dir, CYAN, lbl)) {
                std::cout << YELLOW << "[!] Server disconnected.\n"
                          << RESET;
                break;
            }
        }
    }

    close(clientSock);
    close(serverSock);
    std::cout << RED << "[-] Client " << clientNum
              << " connection closed.\n" << RESET;
}

// ── Main ──────────────────────────────────────────────────────
int main() {

    std::cout << RED << BOLD << R"(
 ██╗  ██╗ █████╗  ██████╗██╗  ██╗███████╗██████╗
 ██║  ██║██╔══██╗██╔════╝██║ ██╔╝██╔════╝██╔══██╗
 ███████║███████║██║     █████╔╝ █████╗  ██████╔╝
 ██╔══██║██╔══██║██║     ██╔═██╗ ██╔══╝  ██╔══██╗
 ██║  ██║██║  ██║╚██████╗██║  ██╗███████╗██║  ██║
 ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝
    MAN-IN-THE-MIDDLE SNIFFER  |  Educational Use
)" << RESET;

    std::cout << YELLOW << BOLD
              << "  [*] Sniffer listening on port : " << SNIFFER_PORT << "\n"
              << "  [*] Forwarding to real server : "
              << REAL_SERVER_IP << ":" << REAL_SERVER_PORT << "\n\n"
              << "  Before AES → plaintext messages visible\n"
              << "  After AES  → binary gibberish only\n"
              << RESET << "\n";

    int snifferSock = socket(AF_INET, SOCK_STREAM, 0);
    int opt = 1;
    setsockopt(snifferSock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    sockaddr_in snifferAddr;
    snifferAddr.sin_family      = AF_INET;
    snifferAddr.sin_port        = htons(SNIFFER_PORT);
    snifferAddr.sin_addr.s_addr = INADDR_ANY;

    if (bind(snifferSock,
             reinterpret_cast<sockaddr*>(&snifferAddr),
             sizeof(snifferAddr)) < 0) {
        perror("Bind failed"); return 1;
    }
    if (listen(snifferSock, 10) < 0) {
        perror("Listen failed"); return 1;
    }

    std::cout << GREEN << BOLD
              << "[*] Sniffer ready. Waiting for victims...\n\n"
              << RESET;

    int clientNum = 1;

    while (true) {
        sockaddr_in clientAddr;
        socklen_t clientLen = sizeof(clientAddr);
        int clientSock = accept(snifferSock,
                                reinterpret_cast<sockaddr*>(&clientAddr),
                                &clientLen);
        if (clientSock < 0) {
            perror("Accept failed");
            continue;
        }

        char clientIP[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &clientAddr.sin_addr,
                  clientIP, sizeof(clientIP));
        std::cout << CYAN << "[+] Connection from: "
                  << clientIP << " (Client " << clientNum << ")"
                  << RESET << "\n";

        // ── KEY FIX: spawn a thread per client ───────────────
        std::thread(handleConnection, clientSock, clientNum).detach();
        clientNum++;
    }

    close(snifferSock);
    return 0;
}
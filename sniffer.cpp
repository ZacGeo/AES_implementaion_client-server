#include <iostream>
#include <cstring>
#include <cstdint>
#include <ctime>
#include <string>
#include <iomanip>
#include <sstream>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>

// ============================================================
//  HACKER SNIFFER — MAN-IN-THE-MIDDLE TCP PROXY
//  Sits between client and server, reads ALL traffic in both
//  directions. Before AES: sees plaintext messages.
//  After AES: sees only binary gibberish.
//
//  HOW IT WORKS:
//  Normal:   Client ──────────────────► Server
//  With us:  Client ──► Sniffer(us) ──► Server
//
//  Port layout:
//    Real server runs on  : 8080
//    Sniffer listens on   : 8081  (clients connect here instead)
//    Sniffer forwards to  : 8080  (the real server)
// ============================================================

// ANSI color codes for terminal output
#define RED     "\033[1;31m"
#define GREEN   "\033[1;32m"
#define YELLOW  "\033[1;33m"
#define CYAN    "\033[1;36m"
#define MAGENTA "\033[1;35m"
#define RESET   "\033[0m"
#define BOLD    "\033[1m"

// The real server address
const char* REAL_SERVER_IP   = "127.0.0.1";
const int   REAL_SERVER_PORT = 8080;
const int   SNIFFER_PORT     = 8081;  // clients connect to this port

// ── Timestamp helper ─────────────────────────────────────────
std::string timestamp() {
    time_t now = time(nullptr);
    char buf[20];
    strftime(buf, sizeof(buf), "%H:%M:%S", localtime(&now));
    return std::string(buf);
}

// ── Hex dump — shows raw bytes (critical for after-AES demo) ─
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

// ── Check if data is printable text ──────────────────────────
bool isPrintable(const std::string& data) {
    for (unsigned char c : data) {
        if (c < 0x20 && c != '\n' && c != '\r' && c != '\t')
            return false;
        if (c > 0x7E) return false;
    }
    return true;
}

// ── Reliably read exactly 'len' bytes from socket ────────────
bool recvAll(int sock, void* data, size_t len) {
    char* ptr = static_cast<char*>(data);
    while (len > 0) {
        ssize_t received = recv(sock, ptr, len, 0);
        if (received <= 0) return false;
        ptr      += received;
        len      -= received;
    }
    return true;
}

// ── Reliably send exactly 'len' bytes to socket ──────────────
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

// ── Read one framed message, log it, forward it ──────────────
//   direction: "CLIENT→SERVER" or "SERVER→CLIENT"
//   color:     ANSI color for this direction
bool interceptMessage(int fromSock, int toSock,
                      const std::string& direction,
                      const char* color,
                      const std::string& label) {

    // Step 1 — Read the 4-byte length header
    uint32_t netLen = 0;
    if (!recvAll(fromSock, &netLen, 4)) return false;

    uint32_t msgLen = ntohl(netLen);

    // Sanity check — same limit as framing.hpp
    if (msgLen == 0 || msgLen > 65536) {
        std::cout << RED << "[!] Suspicious message length: "
                  << msgLen << " — dropping." << RESET << "\n";
        return false;
    }

    // Step 2 — Read the payload
    std::string payload(msgLen, '\0');
    if (!recvAll(fromSock, &payload[0], msgLen)) return false;

    // Step 3 — LOG IT (the hacker reads everything here)
    std::cout << "\n" << BOLD << color
              << "┌─ [" << timestamp() << "] "
              << direction << " ──────────────────────────\n"
              << "│  " << label << "\n"
              << "│  Size   : " << msgLen << " bytes\n";

    if (isPrintable(payload)) {
        // Before AES — readable plaintext
        std::cout << "│  Content: " << GREEN << payload << color << "\n"
                  << "│  Status : " << YELLOW
                  << "⚠  PLAINTEXT — hacker can read this!" << color << "\n";
    } else {
        // After AES — binary garbage
        std::cout << "│  Content: [BINARY DATA — not printable]\n"
                  << "│  Hex    : " << hexDump(payload) << "\n"
                  << "│  Status : " << GREEN
                  << "✓  ENCRYPTED — hacker sees only gibberish." << color << "\n";
    }

    std::cout << "└───────────────────────────────────────────────────\n"
              << RESET << std::flush;

    // Step 4 — Forward it unchanged to the real destination
    if (!sendAll(toSock, &netLen, 4))       return false;  // forward header
    if (!sendAll(toSock, payload.data(), msgLen)) return false;  // forward payload

    return true;
}

// ── One connection handler: Client <──sniffer──> Server ──────
void handleConnection(int clientSock) {

    // Connect to the real server
    int serverSock = socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in serverAddr;
    serverAddr.sin_family      = AF_INET;
    serverAddr.sin_port        = htons(REAL_SERVER_PORT);
    inet_pton(AF_INET, REAL_SERVER_IP, &serverAddr.sin_addr);

    if (connect(serverSock,
                reinterpret_cast<sockaddr*>(&serverAddr),
                sizeof(serverAddr)) < 0) {
        std::cout << RED
                  << "[!] Cannot reach real server on port "
                  << REAL_SERVER_PORT
                  << " — is it running?\n" << RESET;
        close(clientSock);
        return;
    }

    std::cout << CYAN << BOLD
              << "\n[+] New victim connected. "
              << "Proxying to real server...\n" << RESET;

    // Relay loop — alternate reading from each side
    // Uses select() to watch both sockets simultaneously
    while (true) {
        fd_set readSet;
        FD_ZERO(&readSet);
        FD_SET(clientSock, &readSet);
        FD_SET(serverSock, &readSet);
        int maxFd = std::max(clientSock, serverSock) + 1;

        // Block until one of the sockets has data
        int ready = select(maxFd, &readSet, nullptr, nullptr, nullptr);
        if (ready <= 0) break;

        // Data coming FROM client → going TO server
        if (FD_ISSET(clientSock, &readSet)) {
            if (!interceptMessage(clientSock, serverSock,
                                  "CLIENT → SERVER", MAGENTA,
                                  "Client sending to server")) {
                std::cout << YELLOW
                          << "[!] Client disconnected.\n" << RESET;
                break;
            }
        }

        // Data coming FROM server → going TO client
        if (FD_ISSET(serverSock, &readSet)) {
            if (!interceptMessage(serverSock, clientSock,
                                  "SERVER → CLIENT", CYAN,
                                  "Server sending to client")) {
                std::cout << YELLOW
                          << "[!] Server disconnected.\n" << RESET;
                break;
            }
        }
    }

    close(clientSock);
    close(serverSock);
    std::cout << RED << "[-] Connection closed.\n" << RESET;
}

// ── Main: listen for clients on SNIFFER_PORT ─────────────────
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
              << REAL_SERVER_IP << ":" << REAL_SERVER_PORT << "\n"
              << "\n"
              << "  HOW TO USE:\n"
              << "    1. Start the real server on port 8080\n"
              << "    2. Start this sniffer\n"
              << "    3. Connect clients to port 8081 instead of 8080\n"
              << "    4. Watch ALL traffic appear here in real time\n"
              << "\n"
              << "  Before AES → you will see plaintext messages\n"
              << "  After AES  → you will see binary gibberish\n"
              << RESET << "\n";

    // Create the sniffer's listening socket
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
        perror("Bind failed");
        return 1;
    }

    if (listen(snifferSock, 10) < 0) {
        perror("Listen failed");
        return 1;
    }

    std::cout << GREEN << BOLD
              << "[*] Sniffer ready. Waiting for victims...\n\n"
              << RESET;

    // Accept clients one at a time (sequential, no threading needed
    // for a demo — add threads here if you want parallel sessions)
    while (true) {
        sockaddr_in clientAddr;
        socklen_t   clientLen = sizeof(clientAddr);
        int clientSock = accept(snifferSock,
                                reinterpret_cast<sockaddr*>(&clientAddr),
                                &clientLen);
        if (clientSock < 0) {
            perror("Accept failed");
            continue;
        }

        char clientIP[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &clientAddr.sin_addr, clientIP, sizeof(clientIP));
        std::cout << CYAN << "[+] Connection from: "
                  << clientIP << RESET << "\n";

        handleConnection(clientSock);
    }

    close(snifferSock);
    return 0;
}
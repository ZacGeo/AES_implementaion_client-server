#pragma once
#include <sys/socket.h>
#include <netinet/in.h>
#include <string>
#include <cstdint>

// Reliably send exactly 'len' bytes — keeps calling send() until done
inline bool sendAll(int sock, const void* data, size_t len) {
    const char* ptr = static_cast<const char*>(data);
    while (len > 0) {
        ssize_t sent = send(sock, ptr, len, 0);
        if (sent <= 0) return false;
        ptr += sent;
        len -= sent;
    }
    return true;
}

// Reliably receive exactly 'len' bytes
inline bool recvAll(int sock, void* data, size_t len) {
    char* ptr = static_cast<char*>(data);
    while (len > 0) {
        ssize_t received = recv(sock, ptr, len, 0);
        if (received <= 0) return false;
        ptr += received;
        len -= received;
    }
    return true;
}

// Send a framed message: [4-byte length][data]
inline bool sendMsg(int sock, const std::string& msg) {
    uint32_t len = htonl(static_cast<uint32_t>(msg.size())); // htonl = host to network byte order
    if (!sendAll(sock, &len, 4)) return false;
    if (!sendAll(sock, msg.data(), msg.size())) return false;
    return true;
}

// Receive a framed message
inline bool recvMsg(int sock, std::string& msg) {
    uint32_t len = 0;
    if (!recvAll(sock, &len, 4)) return false;
    len = ntohl(len);

    if (len == 0 || len > 65536) return false;
    
    msg.resize(len);
    if (!recvAll(sock, static_cast<void*>(&msg[0]), len)) return false; 
    return true;
}
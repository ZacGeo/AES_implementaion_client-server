#include <iostream>
#include <vector>
#include <string>
#include <thread>
#include <mutex>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <cstring>
#include <condition_variable>
#include <chrono>
#include "framing.hpp"

using namespace std;

mutex serverMutex;
condition_variable partnerCV;

struct Client {
    int socket;
    string name;
    int partnerSocket = -1;
};

vector<Client*> lobby;

void handlePrivateChat(Client* me) {

    // 1. Wait for partner using condition variable — correct placement
    {
        unique_lock<mutex> lock(serverMutex);
        bool paired = partnerCV.wait_for(
            lock,
            chrono::minutes(5),
            [me] { return me->partnerSocket != -1; }
        );

        if (!paired) {
            sendMsg(me->socket, "[Server] No partner found. Disconnecting.");
            close(me->socket);
            delete me;
            return;
        }
    }

    sendMsg(me->socket, "[Server] Partner found! You can now chat.");

    // 2. Chat loop — all framed
    while (true) {
        string buffer;
        if (!recvMsg(me->socket, buffer)) break;
        cout << "[Relay] " << me->name << " -> encrypted bytes: " << buffer.size() << " bytes" << endl;

        lock_guard<mutex> lock(serverMutex);
        if (me->partnerSocket != -1) {
            sendMsg(me->partnerSocket, buffer);
        }
    }

    // 3. Handle disconnect
    lock_guard<mutex> lock(serverMutex);
    if (me->partnerSocket != -1) {
        sendMsg(me->partnerSocket, "[Server] Your partner left the chat.");
    }
    close(me->socket);
    delete me;
}

int main() {
    int serverSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (serverSocket == -1) { perror("Socket creation failed"); return 1; }

    int opt = 1;
    setsockopt(serverSocket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    sockaddr_in addr = {AF_INET, htons(8080), INADDR_ANY};

    if (bind(serverSocket, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("Bind failed"); return 1;
    }
    if (listen(serverSocket, 10) < 0) {
        perror("Listen failed"); return 1;
    }

    cout << "Private Matchmaking Server Online on port 8080..." << endl;

    Client* waitingClient = nullptr;

    while (true) {
        int clientSock = accept(serverSocket, nullptr, nullptr);
        if (clientSock < 0) { perror("Accept failed"); continue; }

        // Receive name using framing — matches client's sendMsg
        string clientName;
        if (!recvMsg(clientSock, clientName)) {
            close(clientSock);
            continue;
        }

        Client* newClient = new Client{clientSock, clientName};

        lock_guard<mutex> lock(serverMutex);
        if (waitingClient == nullptr) {
            waitingClient = newClient;
            sendMsg(clientSock, "[Server] Hi " + newClient->name + ", waiting for a partner...");
            thread(handlePrivateChat, newClient).detach(); // starts and blocks on partnerCV
        } else {
            newClient->partnerSocket = waitingClient->socket;
            waitingClient->partnerSocket = newClient->socket;
            partnerCV.notify_all(); // wake up the waiting thread

            sendMsg(newClient->socket, "[Server] Connected to your partner!");
            sendMsg(waitingClient->socket, "[Server] Connected to your partner!");

            thread(handlePrivateChat, newClient).detach();
            waitingClient = nullptr;
        }
    }
    return 0;
}
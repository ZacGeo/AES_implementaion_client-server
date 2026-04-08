#include <iostream>
#include <vector>
#include <string>
#include <thread>
#include <mutex>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <cstring>

using namespace std;

struct Client {
    int socket;
    string name;
    int partnerSocket = -1; // Socket of the person they are talking to
};

// Global state
vector<Client*> lobby; 
mutex serverMutex;

void handlePrivateChat(Client* me) {
    char buffer[1024];
    
    // 1. Wait until a partner is assigned
    while (true) {
        {
            lock_guard<mutex> lock(serverMutex);
            if (me->partnerSocket != -1) break;
        }
        usleep(100000); // Sleep 100ms to save CPU
    }

    send(me->socket, "[Server] Partner found! You can now chat.\n", 42, 0);

    // 2. Chat loop - Only relay to the partner
    while (true) {
        memset(buffer, 0, sizeof(buffer));
        int bytesReceived = recv(me->socket, buffer, sizeof(buffer), 0);

        if (bytesReceived <= 0) break;

        {
            lock_guard<mutex> lock(serverMutex);
            if (me->partnerSocket != -1) {
                send(me->partnerSocket, buffer, bytesReceived, 0);
            }
        }
    }

    // 3. Handle Disconnect
    lock_guard<mutex> lock(serverMutex);
    if (me->partnerSocket != -1) {
        send(me->partnerSocket, "[Server] Your partner left the chat.", 36, 0);
        // Logic to handle remaining partner could go here
    }
    close(me->socket);
    delete me;
}

int main() {
    int serverSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (serverSocket == -1) {
        perror("Socket creation failed");
        return 1;
    }

    // This line allows you to rerun the server immediately without "Address already in use" errors
    int opt = 1;
    setsockopt(serverSocket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    sockaddr_in addr = {AF_INET, htons(8080), INADDR_ANY};
    
    if (bind(serverSocket, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("Bind failed");
        return 1;
    }

    if (listen(serverSocket, 10) < 0) {
        perror("Listen failed");
        return 1;
    }

    cout << "Private Matchmaking Server Online on port 8080..." << endl;

    Client* waitingClient = nullptr;

    while (true) {
        int clientSock = accept(serverSocket, nullptr, nullptr);
        if (clientSock < 0) {
            perror("Accept failed");
            continue;
        }
        
        // Receive name
        char nameBuf[1024] = {0};
        recv(clientSock, nameBuf, sizeof(nameBuf), 0);
        
        Client* newClient = new Client{clientSock, string(nameBuf)};
        
        lock_guard<mutex> lock(serverMutex);
        if (waitingClient == nullptr) {
            waitingClient = newClient;
            string msg = "[Server] Hi " + newClient->name + ", waiting for a partner...\n";
            send(clientSock, msg.c_str(), msg.length(), 0);
        } else {
            newClient->partnerSocket = waitingClient->socket;
            waitingClient->partnerSocket = newClient->socket;
            
            // Notify both that they are paired
            string startMsg = "[Server] Connected to your partner!\n";
            send(newClient->socket, startMsg.c_str(), startMsg.length(), 0);
            send(waitingClient->socket, startMsg.c_str(), startMsg.length(), 0);

            // Start the thread for the WAITING client now that they have a partner
            thread(handlePrivateChat, waitingClient).detach();
            waitingClient = nullptr; 
        }
        
        // Start the thread for the NEW client
        thread(handlePrivateChat, newClient).detach();
    }
    return 0;
}
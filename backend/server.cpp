#include <iostream>
#include <vector>
#include <string>
#include <thread>
#include <mutex>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <algorithm>
#include <cstring>

using namespace std;

// We need a mutex to protect the shared vector from simultaneous access
vector<int> clients;
mutex clientsMutex;

void handleClient(int clientSocket) {
    char buffer[1024];
    while (true) {
        memset(buffer, 0, sizeof(buffer));
        int bytesReceived = recv(clientSocket, buffer, sizeof(buffer), 0);

        if (bytesReceived <= 0) {
            cout << "A client disconnected." << endl;
            break;
        }

        string msg = string(buffer);
        cout << "Relaying: " << msg << endl;

        // --- ROUTING LOGIC ---
        lock_guard<mutex> lock(clientsMutex);
        for (int socket : clients) {
            if (socket != clientSocket) { // Don't send it back to the sender
                send(socket, msg.c_str(), msg.length(), 0);
            }
        }
    }

    // Cleanup when client leaves
    close(clientSocket);
    lock_guard<mutex> lock(clientsMutex);
    clients.erase(remove(clients.begin(), clients.end(), clientSocket), clients.end());
}

int main() {
    int serverSocket = socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in serverAddress;
    serverAddress.sin_family = AF_INET;
    serverAddress.sin_port = htons(8080);
    serverAddress.sin_addr.s_addr = INADDR_ANY;

    bind(serverSocket, (struct sockaddr*)&serverAddress, sizeof(serverAddress));
    listen(serverSocket, 10);

    cout << "Server Multi-Client Hub started on port 8080..." << endl;

    while (true) {
        int clientSocket = accept(serverSocket, nullptr, nullptr);
        
        {
            lock_guard<mutex> lock(clientsMutex);
            clients.push_back(clientSocket);
        }

        cout << "New connection! Total clients: " << clients.size() << endl;

        // Spawn a thread for this specific client
        thread t(handleClient, clientSocket);
        t.detach(); // Let the thread run independently
    }

    close(serverSocket);
    return 0;
}
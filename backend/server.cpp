#include <iostream>
#include <cstring>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>

using namespace std;

int main() { 
    int serverSocket = socket(AF_INET, SOCK_STREAM, 0);

    sockaddr_in serverAddress;
    serverAddress.sin_family = AF_INET;
    serverAddress.sin_port = htons(8080);
    serverAddress.sin_addr.s_addr = INADDR_ANY;

    bind(serverSocket, (struct sockaddr*)&serverAddress, sizeof(serverAddress));
    listen(serverSocket, 5);

    cout << "Server is listening on port 8080..." << endl;

    int clientSocket = accept(serverSocket, nullptr, nullptr);
    cout << "Client connected!" << endl;

    char buffer[1024] = {0};
    string response;

    // Start the communication loop
    while (true) {
        // Clear buffer and wait for client message
        memset(buffer, 0, sizeof(buffer));
        int bytesReceived = recv(clientSocket, buffer, sizeof(buffer), 0);
        
        // If bytesReceived is 0 or less, the client disconnected
        if (bytesReceived <= 0) {
            cout << "Client disconnected or logged off." << endl;
            break;
        }

        string receivedMessage(buffer);
        if (receivedMessage == "exit") {
            cout << "Client initiated log off." << endl;
            break;
        }

        cout << "Client: " << buffer << endl;

        // Type and send a reply
        cout << "You: ";
        getline(cin, response);
        send(clientSocket, response.c_str(), response.length(), 0);
        
        if (response == "exit") {
            cout << "Logging off..." << endl;
            break;
        }
    }

    // Always close BOTH sockets on the server side
    close(clientSocket);
    close(serverSocket);
    return 0;
}
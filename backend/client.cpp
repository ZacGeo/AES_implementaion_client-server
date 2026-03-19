#include <iostream>
#include <cstring>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

using namespace std;

int main() {
    int clientSocket = socket(AF_INET, SOCK_STREAM, 0);

    sockaddr_in serverAddress;
    serverAddress.sin_family = AF_INET;
    serverAddress.sin_port = htons(8080);
    serverAddress.sin_addr.s_addr = INADDR_ANY;

    if (connect(clientSocket, (struct sockaddr*)&serverAddress, sizeof(serverAddress)) < 0) {
        cout << "Connection failed!" << endl;
        return 1;
    }

    cout << "Connected to the server! Type 'exit' to log off." << endl;

    char buffer[1024] = {0};
    string message;

    // Start the communication loop
    while (true) {
        cout << "You: ";
        getline(cin, message); // Get typed input from user

        // Send the message
        send(clientSocket, message.c_str(), message.length(), 0);

        // If user typed "exit", break the loop
        if (message == "exit") {
            cout << "Logging off..." << endl;
            break;
        }

        // Clear the buffer and wait for server response
        memset(buffer, 0, sizeof(buffer)); 
        int bytesReceived = recv(clientSocket, buffer, sizeof(buffer), 0);
        
        if (bytesReceived <= 0) {
            cout << "Server disconnected." << endl;
            break;
        }

        cout << "Server: " << buffer << endl;
    }

    close(clientSocket);
    return 0;
}
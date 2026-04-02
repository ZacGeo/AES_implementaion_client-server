#include <iostream>
#include <cstring>
#include <thread>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

using namespace std;

// This function runs in the background to listen for messages from the server
void receiveMessages(int clientSocket) {
    char buffer[1024];
    while (true) {
        memset(buffer, 0, sizeof(buffer));
        int bytesReceived = recv(clientSocket, buffer, sizeof(buffer), 0);
        
        if (bytesReceived <= 0) {
            cout << "\n[System] Connection lost or server shut down." << endl;
            exit(0); // Exit the whole program if the server drops
        }

        // Print the message received from another client (via the server)
        cout << "\nMessage: " << buffer << "\nYou: " << flush;
    }
}

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

    cout << "Connected! Type your messages below (type 'exit' to quit):" << endl;

    // Start the receiver thread
    thread receiveThread(receiveMessages, clientSocket);
    receiveThread.detach(); // Let it run independently

    string message;
    while (true) {
        cout << "You: ";
        getline(cin, message);

        if (message == "exit") {
            break;
        }

        send(clientSocket, message.c_str(), message.length(), 0);
    }

    close(clientSocket);
    return 0;
}
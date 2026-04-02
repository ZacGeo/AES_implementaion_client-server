#include <iostream>
#include <cstring>
#include <thread>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

using namespace std;

void receiveMessages(int clientSocket) {
    char buffer[1024];
    while (true) {
        memset(buffer, 0, sizeof(buffer));
        int bytesReceived = recv(clientSocket, buffer, sizeof(buffer), 0);
        
        if (bytesReceived <= 0) {
            cout << "\n[System] Connection lost." << endl;
            exit(0);
        }

        // Print the message (which now includes the sender's name)
        cout << "\n" << buffer << "\nYou: " << flush;
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

    // Ask for a username
    string name;
    cout << "Enter your name: ";
    getline(cin, name);
    cout << "Welcome, " << name << "! (type 'exit' to quit)\n" << endl;

    thread receiveThread(receiveMessages, clientSocket);
    receiveThread.detach();

    string message;
    while (true) {
        cout << "You: ";
        getline(cin, message);

        if (message == "exit") break;

        // Format the message as "Name: Message"
        string formattedMessage = name + ": " + message;
        send(clientSocket, formattedMessage.c_str(), formattedMessage.length(), 0);
    }

    close(clientSocket);
    return 0;
}
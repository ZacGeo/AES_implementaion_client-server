#include <iostream>
#include <cstring>
#include <thread>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

using namespace std;

string myName;

void receiveMessages(int clientSocket) {
    char buffer[1024];
    while (true) {
        memset(buffer, 0, sizeof(buffer));
        if (recv(clientSocket, buffer, sizeof(buffer), 0) <= 0) {
            cout << "\n[Disconnected]" << endl;
            exit(0);
        }
        // \r clears the current line so the incoming message looks clean
        cout << "\r" << buffer << endl;
        cout << myName << ": " << flush; 
    }
}

int main() {
    int clientSocket = socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in serverAddress;
    serverAddress.sin_family = AF_INET;
    serverAddress.sin_port = htons(8080);
    serverAddress.sin_addr.s_addr = INADDR_ANY;

    if (connect(clientSocket, (struct sockaddr*)&serverAddress, sizeof(serverAddress)) < 0) {
        cout << "Connection error." << endl;
        return 1;
    }

    cout << "Enter your name: ";
    getline(cin, myName);
    
    // Step 1: Send only the name for the server's registry
    send(clientSocket, myName.c_str(), myName.length(), 0);

    thread(receiveMessages, clientSocket).detach();

    string message;
    while (true) {
        cout << myName << ": " << flush;
        getline(cin, message);

        if (message == "exit") break;
        if (message.empty()) continue;

        // Step 2: Send the message formatted with the name
        string formatted = myName + ": " + message;
        send(clientSocket, formatted.c_str(), formatted.length(), 0);
    }

    close(clientSocket);
    return 0;
}
#include <iostream>
#include <cstring>
#include <thread>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <arpa/inet.h>
#include "framing.hpp"

using namespace std;

string myName;

void receiveMessages(int clientSocket) {
    while (true) {
        string buffer;
        if (!recvMsg(clientSocket, buffer)) {
            cout << "\n[Disconnected]" << endl;
            exit(0);
        }
        cout << "\r" << buffer << endl;
        cout << myName << ": " << flush;
    }
}

int main() {
    int clientSocket = socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in serverAddress;
    serverAddress.sin_family = AF_INET;
    serverAddress.sin_port = htons(8080);

    string serverIP;
    cout << "Enter server IP (or press Enter for localhost): ";
    getline(cin, serverIP);
    if (serverIP.empty()) serverIP = "127.0.0.1"; // fixed in client2 too
    serverAddress.sin_addr.s_addr = inet_addr(serverIP.c_str());

    if (connect(clientSocket, (struct sockaddr*)&serverAddress, sizeof(serverAddress)) < 0) {
        cout << "Connection error." << endl;
        return 1;
    }

    cout << "Enter your name: ";
    getline(cin, myName);

    sendMsg(clientSocket, myName);

    thread(receiveMessages, clientSocket).detach();

    string message;
    while (true) {
        cout << myName << ": " << flush;
        getline(cin, message);
        if (message == "exit") break;
        if (message.empty()) continue;
        sendMsg(clientSocket, myName + ": " + message);
    }

    close(clientSocket);
    return 0;
}
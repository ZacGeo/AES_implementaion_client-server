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

        // PLAINTEXT MODE:
        // No AES decryption is performed.
        // Whatever the server sends is displayed directly.
        cout << "\r" << buffer << endl;

        cout << myName << ": " << flush;
    }
}

int main() {
    int clientSocket = socket(AF_INET, SOCK_STREAM, 0);

    if (clientSocket < 0) {
        cout << "Socket creation error." << endl;
        return 1;
    }

    sockaddr_in serverAddress{};
    serverAddress.sin_family = AF_INET;
    serverAddress.sin_port = htons(8081);

    string serverIP;
    cout << "Enter server IP (or press Enter for localhost): ";
    getline(cin, serverIP);

    if (serverIP.empty())
        serverIP = "127.0.0.1";

    serverAddress.sin_addr.s_addr = inet_addr(serverIP.c_str());

    if (connect(clientSocket,
                (struct sockaddr*)&serverAddress,
                sizeof(serverAddress)) < 0) {
        cout << "Connection error." << endl;
        close(clientSocket);
        return 1;
    }

    cout << "Enter your name: ";
    getline(cin, myName);

    // Name registration is sent in plaintext.
    sendMsg(clientSocket, myName);

    // Receive messages in parallel.
    thread(receiveMessages, clientSocket).detach();

    string message;

    while (true) {
        cout << myName << ": " << flush;
        getline(cin, message);

        if (message == "exit")
            break;

        if (message.empty())
            continue;

        // PLAINTEXT MODE:
        // The message is sent exactly as readable text.
        // No AES_CBC_Encrypt() call is made here.
        string formatted = myName + ": " + message;

        sendMsg(clientSocket, formatted);
    }

    close(clientSocket);
    return 0;
}

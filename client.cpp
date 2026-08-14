#include <iostream>
#include <cstring>
#include <thread>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <arpa/inet.h>
#include "framing.hpp"
#include "aes.hpp"          // ← NEW

using namespace std;

// Shared AES key — both clients must use the same key
static const uint8_t AES_KEY[16] = {
    0x2b,0x7e,0x15,0x16, 0x28,0xae,0xd2,0xa6,
    0xab,0xf7,0x15,0x88, 0x09,0xcf,0x4f,0x3c
};

string myName;

void receiveMessages(int clientSocket) {
    while (true) {
        string buffer;
        if (!recvMsg(clientSocket, buffer)) {
            cout << "\n[Disconnected]" << endl;
            exit(0);
        }

        // Server notifications are plain text — don't decrypt them
        if (buffer.rfind("[Server]", 0) == 0) {
            cout << "\r" << buffer << endl;
        } else {
            // Decrypt the incoming message               // ← NEW
            try {
                string decrypted = AES_CBC_Decrypt(buffer, AES_KEY);
                cout << "\r" << decrypted << endl;
            } catch (...) {
                cout << "\r[Error: could not decrypt message]" << endl;
            }
        }
        cout << myName << ": " << flush;
    }
}

int main() {
    int clientSocket = socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in serverAddress;
    serverAddress.sin_family = AF_INET;
    serverAddress.sin_port = htons(8081);

    string serverIP;
    cout << "Enter server IP (or press Enter for localhost): ";
    getline(cin, serverIP);
    if (serverIP.empty()) serverIP = "127.0.0.1";
    serverAddress.sin_addr.s_addr = inet_addr(serverIP.c_str());

    if (connect(clientSocket, (struct sockaddr*)&serverAddress, sizeof(serverAddress)) < 0) {
        cout << "Connection error." << endl;
        return 1;
    }

    cout << "Enter your name: ";
    getline(cin, myName);

    // Name registration is plain text — server needs to read it
    sendMsg(clientSocket, myName);

    thread(receiveMessages, clientSocket).detach();

    string message;
    while (true) {
        cout << myName << ": " << flush;
        getline(cin, message);
        if (message == "exit") break;
        if (message.empty()) continue;

        // Encrypt before sending                        // ← NEW
        string formatted  = myName + ": " + message;
        string encrypted  = AES_CBC_Encrypt(formatted, AES_KEY);
        sendMsg(clientSocket, encrypted);
    }

    close(clientSocket);
    return 0;
}
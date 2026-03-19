#include  <cstring>
#include  <unistd.h>
#include  <sys/socket.h>
#include  <netinet/in.h>
#include <iostream>

using namespace std;

int main() { 
    //creating socket
    int serverSocket = socket(AF_INET, SOCK_STREAM, 0);

    //Defining Server Address
    sockaddr_in serverAddress;
    serverAddress.sin_family = AF_INET;
    serverAddress.sin_port = htons(8080);
    serverAddress.sin_addr.s_addr = INADDR_ANY;

    //Bind Socket to Address
    bind(serverSocket, (struct sockaddr*)&serverAddress, sizeof(serverAddress));

    //Listen for incoming connections
    listen(serverSocket, 5);

    //Accept Client Connection
    int clientSocket = accept(serverSocket, nullptr,nullptr);

    //Receive Data from Client
    char buffer[1024] = {0};
    recv(clientSocket, buffer, sizeof(buffer), 0);
    cout <<"Message from client: " << buffer << endl;

    close(serverSocket);
    

}
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <asm-generic/socket.h>

int main(){
    // Socket variables
    int groundStationSocket, spacecraftSocket;
    struct sockaddr_in groundStationAddr, spacecraftAddr;
    unsigned int spacecraftAddrLen = sizeof(spacecraftAddr);

    // Create ground station socket
    groundStationSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (groundStationSocket < 0) {
        perror("socket(): Failed to create ground station socket");
        return -1;
    }

    // Define ground station address
    memset(&groundStationAddr, 0, sizeof(groundStationAddr));
    groundStationAddr.sin_family = AF_INET;
    groundStationAddr.sin_addr.s_addr = htonl(INADDR_ANY);
    groundStationAddr.sin_port = htons(44500);

    // Attach socket to the port with SO_REUSEADDR and SO_REUSEPORT
    // Temporary fix for "Address already in use" error for development purposes
    int reuse = 1;
    if (setsockopt(groundStationSocket, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) < 0) {
        perror("setsockopt(): SO_REUSEADDR failed");
        return -1;
    }

    if (setsockopt(groundStationSocket, SOL_SOCKET, SO_REUSEPORT, &reuse, sizeof(reuse)) < 0) {
        perror("setsockopt(): SO_REUSEPORT failed");
        return -1;
    }

    // Bind ground station socket
    if (bind(groundStationSocket, (struct sockaddr*)& groundStationAddr, sizeof(groundStationAddr)) < 0){
        perror("bind(): Failed to bind ground station socket");
        return -1;
    }

    // Listen for incoming connections
    if (listen(groundStationSocket, 1) < 0){
        perror("listen(): Failed to listen for incoming connections");
        return -1;
    }
    printf("Ground station listening for incoming connections on port %d...\n", 44500);

    // Loop to accept and handle incoming connections
    while (1) {
        // Accept incoming connection from spacecraft
        spacecraftSocket = accept(groundStationSocket, (struct sockaddr*)& spacecraftAddr, &spacecraftAddrLen);
        if (spacecraftSocket < 0){
            perror("accept(): Failed to accept incoming connection");
            continue;
        }
        printf("Accepted connection from spacecraft: %s:%d\n", inet_ntoa(spacecraftAddr.sin_addr), ntohs(spacecraftAddr.sin_port));

        // Receive message from spacecraft
        char message[256];
        ssize_t bytesReceived = recv(spacecraftSocket, message, sizeof(message) - 1, 0);
        if (bytesReceived <= 0){
            perror("recv(): Failed to receive message from spacecraft");
            continue;
        }

        // Null-terminate
        message[bytesReceived] = '\0';
        printf("Received message from spacecraft: %s\n", message);

        // Send acknowledgment back to spacecraft
        char ack[256];
        snprintf(ack, sizeof(ack), "Message received from spacecraft %s:%d\n", inet_ntoa(spacecraftAddr.sin_addr), ntohs(spacecraftAddr.sin_port));
        send(spacecraftSocket, ack, strlen(ack), 0);
        printf("Sent acknowledgment to spacecraft.\n");

        // Close spacecraft socket
        close(spacecraftSocket);

        // If command is "exit", break the loop and terminate the program
        if (strcmp(message, "exit") == 0) {
            printf("Exit command received. Shutting down ground station.\n");
            break;
        }
    }

    // Close ground station socket
    close(groundStationSocket);
    return 0;
}
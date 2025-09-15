#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>

int main() {
    // Socket variables
    int spacecraftSocket;
    struct sockaddr_in groundStationAddr;

    // Create spacecraft socket
    spacecraftSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (spacecraftSocket < 0) {
        perror("socket(): Failed to create spacecraft socket");
        return -1;
    }

    // Define ground station address
    memset(&groundStationAddr, 0, sizeof(groundStationAddr));
    groundStationAddr.sin_family = AF_INET;
    groundStationAddr.sin_addr.s_addr = inet_addr("127.0.0.1");
    groundStationAddr.sin_port = htons(44500);

    // Connect to ground station
    if (connect(spacecraftSocket, (struct sockaddr*)& groundStationAddr, sizeof(groundStationAddr)) < 0){
        perror("connect(): Failed to connect to ground station");
        return -1;
    }

    // Prompt user for message input
    char message[256];
    printf("Enter message to send to ground station: ");

    // Read input and remove trailing newline
    fgets(message, sizeof(message), stdin);
    message[strcspn(message, "\n")] = '\0';
    
    // Send message to ground station
    send(spacecraftSocket, message, strlen(message), 0);

    // Receive acknowledgment from ground station
    char ack[256];
    if (recv(spacecraftSocket, ack, sizeof(ack) - 1, 0) <= 0){
        perror("recv(): Failed to receive acknowledgment from ground station");
        return -1;
    }

    // Null-terminate
    ack[255] = '\0';
    printf("Received acknowledgment from ground station: \n >>> %s\n", ack);

    return 0;
}
/*
** webserver.c
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>

#define BACKLOG 10 // how many pending connections queue holds

/**
3 *
2 * Derives a sockaddr_in structure from the provided host and port information.
4 * @param host The host (IP address or hostname) to be resolved into a network
address.
5 * @param port The port number to be converted into network byte order.
6 *
7 * @return A sockaddr_in structure representing the network address derived from
the host and port.
8 */
static struct sockaddr_in derive_sockaddr(const char *host, const char *port)
{
    struct addrinfo hints = {
        .ai_family = AF_INET, // IPv4
    };
    struct addrinfo *result_info;
    // Resolve the host (IP address or hostname) into a list of possible addresses.
    int returncode = getaddrinfo(host, port, &hints, &result_info);
    if (returncode)
    {
        fprintf(stderr, "Error␣parsing␣host/port");
        exit(EXIT_FAILURE);
    }
    // Copy the sockaddr_in structure from the first address in the list
    struct sockaddr_in result = *((struct sockaddr_in *)result_info->ai_addr);
    // Free the allocated memory for the result_info
    freeaddrinfo(result_info);
    return result;
}

int main(int argc, char *argv[])
{
    if (argc != 3)
    {
        fprintf(stderr, "Usage: %s <host> <port>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    const char *host = argv[1];
    const char *port = argv[2];

    printf("Server address:\n");
    printf("IP Address: %s\n", host);
    printf("Port: %s\n", port);

    struct addrinfo hints, *res;
    socklen_t addr_size;

    struct sockaddr_storage their_addr; // Copied from Beej's Guide till line
    int sockfd, new_fd;                 // listen on sock_fd, new connection on new_fd

    const char *accept_message = "Reply";
    int len, bytes_sent;

    // first, load up address structs with getaddrinfo():

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC; // use IPv4 or IPv6, whichever
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE; // fill in my IP for me

    getaddrinfo(NULL, port, &hints, &res);

    // make a socket:

    sockfd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (sockfd < 0)
    {
        perror("Error creating socket");
        exit(EXIT_FAILURE);
    }

    int optval = 1;
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval)) < 0) // Enable address reuse
    {
        perror("Error setting socket options");
        exit(EXIT_FAILURE);
    }

    // bind it to the port we passed in to getaddrinfo():
    if (bind(sockfd, res->ai_addr, res->ai_addrlen) < 0)
    {
        perror("Error binding socket");
        exit(EXIT_FAILURE);
    }
    freeaddrinfo(res); // all done with this structure

    // start listening for connections:
    if (listen(sockfd, BACKLOG) < 0)
    {
        perror("Error listening on socket");
        exit(EXIT_FAILURE);
    }

    printf("Server is listening on %s:%s\n", host, port);

    while (1)
    {
        // now accept an incoming connection:
        addr_size = sizeof their_addr;
        new_fd = accept(sockfd, (struct sockaddr *)&their_addr, &addr_size);
        if (new_fd < 0)
        {
            perror("Error accepting connection");
            exit(EXIT_FAILURE);
        }
        printf("Connection accepted from %s:%d\n",
               inet_ntoa(((struct sockaddr_in *)&their_addr)->sin_addr),
               ntohs(((struct sockaddr_in *)&their_addr)->sin_port));

        len = strlen(accept_message);
        bytes_sent = send(new_fd, accept_message, len, 0);
        if (bytes_sent < 0)
        {
            perror("Error sending message");
            exit(EXIT_FAILURE);
        }
        printf("Sent %d bytes: %s\n", bytes_sent, accept_message);
        close(new_fd);
    }

    close(sockfd);
    return 0;
}

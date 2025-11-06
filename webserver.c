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
//Test Kommentar =)
#define BACKLOG 10      // how many pending connections queue holds
#define MAXDATASIZE 100 // max number of bytes we can get at once

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

    struct addrinfo hints, *res;
    socklen_t addr_size;

    struct sockaddr_storage their_addr; // Copied from Beej's Guide till line
    int sockfd, new_fd;                 // listen on sock_fd, new connection on new_fd

    const char *accept_message = "Reply\r\n\r\n";
    const char *bad_request_response =
    "HTTP/1.1 400 Bad Request\r\n"
    "Content-Length: 0\r\n"
    "\r\n";

    int bytes_sent;

    // first, load up address structs with getaddrinfo():

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET; // use IPv4
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = 0; // use my IP

    if (getaddrinfo(host, port, &hints, &res) != 0)
    {
        perror("Error getting address info");
        exit(EXIT_FAILURE);
    }

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

        // receive data
        size_t buf_len = 0;
        ssize_t n;
        char buf[MAXDATASIZE];

        memset(buf, 0, MAXDATASIZE); // Clear the buffer before receiving data

        while ((n = recv(new_fd, buf + buf_len, MAXDATASIZE - buf_len - 1, 0)) > 0)
        {
            buf_len += n;
            buf[buf_len] = '\0';

            char *packet_end;
            while ((packet_end = strstr(buf, "\r\n\r\n")) != NULL)
            {
                // Found one complete HTTP packet
                if (send(new_fd, bad_request_response, strlen(bad_request_response), 0) < 0)
                {
                    perror("Error sending reply");
                    close(new_fd);
                    break;
                }

                char *packet = strndup(buf, packet_end - buf + 4);

                printf("Processed a packet and sent reply.\nPacket data:\n%s\n", packet);

                // Move remaining unprocessed data to the start
                size_t processed_length = packet_end - buf + 4; // include "\r\n\r\n"
                size_t remaining = buf_len - processed_length;
                memmove(buf, buf + processed_length, remaining);
                buf_len = remaining;
                buf[buf_len] = '\0';
            }
        }

        close(new_fd);
    }

    close(sockfd);
    return 0;
}

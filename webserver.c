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

#define BACKLOG 10      // how many pending connections queue holds
#define MAXDATASIZE 100 // max number of bytes we can get at once

enum Method
{
    GET = 1,
    POST = 2,
    PUT = 3,
    DELETE = 4,
    UNKNOWN = 5,
    BADREQUEST = 0
};

typedef struct Resource
{ // ChatGPT till line 42
    char *path;
    char *content;
    struct Resource *next;
} Resource;

Resource *resources = NULL;

// Helper: find resource
Resource *find_resource(const char *path)
{
    for (Resource *r = resources; r != NULL; r = r->next)
    {
        if (strcmp(r->path, path) == 0)
            return r;
    }
    return NULL;
}

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
/**
 * Checks if the given HTTP request.
 * @param request The HTTP request string to be checked.
 * @return req type, Null if invalid
 */

int check_http_request(const char *request)
{
    // Anfragen sind inkorrekt, wenn
    // • keine Startzeile erkannt wird, also die erste Zeile nicht dem Muster <Method> <URI> <HTTPVersion>\r\n entspricht oder
    // • Ihre Header nicht dem Muster <Key>: <Value> entsprechen.
    char method[16], uri[128], version[16];
    if (sscanf(request, "%15s %127s %15s\r\n", method, uri, version) != 3)
        return BADREQUEST; // Bad Request

    char *newline = strchr(request, '\n');
    if (!newline)
        return BADREQUEST;
    char *line_start = newline + 1;
    while (line_start && *line_start != '\r' && *line_start != '\n')
    {
        char key[128], value[256];
        if (sscanf(line_start, "%127[^:]: %255[^\r\n]\r\n", key, value) != 2)
        {
            return BADREQUEST; // Bad Request
        }
        char *next = strchr(line_start, '\n');
        if (!next)
            break;
        line_start = next + 1;
    }

    printf("Method: %s\n", method);
    if (strcmp(method, "GET") == 0)
        return GET;
    else if (strcmp(method, "POST") == 0)
        return POST;
    else if (strcmp(method, "PUT") == 0)
        return PUT;
    else if (strcmp(method, "DELETE") == 0)
        return DELETE;
    else
        return UNKNOWN; // Unsupported Method
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

    // const char *accept_message = "Reply\r\n\r\n";
    const char *bad_request_response =
        "HTTP/1.1 400 Bad Request\r\n"
        "Content-Length: 0\r\n"
        "\r\n";
    const char *not_found_response =
        "HTTP/1.1 404 Not Found\r\n"
        "Content-Length: 0\r\n"
        "\r\n";
    const char *code_501 =
        "HTTP/1.1 501 Not Implemented\r\n"
        "Content-Length: 0\r\n"
        "\r\n";
    const char *no_content =
        "HTTP/1.1 204 No Content\r\n"
        "Content-Length: 0\r\n"
        "\r\n";
    const char *created =
        "HTTP/1.1 201 Created\r\n"
        "Content-Length: 0\r\n"
        "\r\n";

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
                char *packet = strndup(buf, packet_end - buf + 4);

                int reqType = check_http_request(packet);
                char *response = NULL;
                char response_buf[512];
                size_t response_len = 0;

                char method[16], uri[256], version[16];
                if (sscanf(packet, "%15s %255s %15s", method, uri, version) != 3)
                    reqType = BADREQUEST;

                switch (reqType)
                {
                case GET:
                {
                    /* Valid GET request so inspect URI and serve static content */
                    const char *body = NULL;
                    if (strncmp(uri, "/static/", 8) == 0)
                    {
                        const char *key = uri + 8;
                        if (strcmp(key, "foo") == 0)
                            body = "Foo";
                        else if (strcmp(key, "bar") == 0)
                            body = "Bar";
                        else if (strcmp(key, "baz") == 0)
                            body = "Baz";
                    }
                    // Check dynamic content
                    if (strncmp(uri, "/dynamic/", 9) == 0)
                    {
                        const char *key = uri + 9;
                        Resource *res = find_resource(key);
                        if (res)
                            body = res->content;
                    }

                    if (body)
                    {
                        int len = snprintf(response_buf, sizeof response_buf,
                                           "HTTP/1.1 200 OK\r\nContent-Length: %zu\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n%s",
                                           strlen(body), body);
                        if (len > 0)
                            response_len = (size_t)len;
                    }
                    else
                    {
                        response = not_found_response;
                    }
                }
                break;

                case PUT:
                    response = no_content;
                    break;
                case DELETE:
                    response = no_content;
                    break;
                case UNKNOWN:
                    response = code_501;
                    break;
                case BADREQUEST:
                    response = bad_request_response;
                    break;
                default:
                    response = code_501;
                    break;
                }

                ssize_t sent = 0;
                if (response_len > 0) // custom response in buffer
                {
                    sent = send(new_fd, response_buf, response_len, 0);
                }
                else if (response) // predefined response
                {
                    sent = send(new_fd, response, strlen(response), 0);
                }

                if (sent < 0)
                {
                    perror("Error sending reply");
                    close(new_fd);
                    break;
                }
                printf("Processed a packet and sent reply.\nPacket data:\n%s\nResponse:\n%s", packet, response);

                // Move remaining unprocessed data to the start
                size_t processed_length = packet_end - buf + 4; // include "\r\n\r\n"
                size_t remaining = buf_len - processed_length;
                memmove(buf, buf + processed_length, remaining);
                buf_len = remaining;
                buf[buf_len] = '\0';
                free(packet);
            }
        }

        close(new_fd);
    }

    close(sockfd);
    return 0;
}

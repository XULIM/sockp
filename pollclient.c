#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <poll.h>
#include <errno.h>
#include <netdb.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>

#define PORT "6969"

enum
{
    BUFLEN = 256,
};

void *get_in_addr(struct sockaddr *s)
{
    if (s->sa_family == AF_INET)
    {
        return &(((struct sockaddr_in*)s)->sin_addr);
    }
    return &(((struct sockaddr_in6*)s)->sin6_addr);
}


int main(int argc, char **argv)
{
    int serverfd, status, nbytes, npoll;
    char buf[BUFLEN], s[INET6_ADDRSTRLEN];
    struct addrinfo hints, *p, *serverinfo;
    struct pollfd fds[2]; // for stdin and serverfd

    if (argc != 2)
    {
        fputs("Usage: pollclient hostname", stderr);
        exit(1);
    }

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    status = getaddrinfo(argv[1], PORT, &hints, &serverinfo);
    if (status != 0)
    {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(status));
        exit(1);
    }

    for (p = serverinfo; p != NULL; p = p->ai_next)
    {
        serverfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (serverfd == -1)
        {
            perror("client: socket");
            continue;
        }

        if (connect(serverfd, p->ai_addr, p->ai_addrlen) == -1)
        {
            close(serverfd);
            perror("client: connect");
            continue;
        }

        break;
    }
    
    if (p == NULL)
    {
        fputs("clinet: failed to connect", stderr);
        freeaddrinfo(serverinfo);
        exit(1);
    }

    inet_ntop(p->ai_family, get_in_addr((struct sockaddr*)p->ai_addr),
            s, sizeof(s));
    printf("client: connected to server %s.\n", s);

    freeaddrinfo(serverinfo);
    
    fds[0].fd = STDIN_FILENO;
    fds[0].events = POLLIN;
    fds[0].revents = 0;

    fds[1].fd = serverfd;
    fds[1].events = POLLIN;
    fds[1].revents = 0;

    for (;;)
    {
        npoll = poll(fds, 2, -1);
        if (npoll == -1)
        {
            perror("client: poll");
            close(serverfd);
            exit(1);
        }

        if (fds[0].revents & POLLIN)
        {
            if (fgets(buf, BUFLEN, stdin) == NULL)
            {
                puts("Disconnecting...");
                close(serverfd);
                exit(0);
            }

            nbytes = strlen(buf);
            if (send(serverfd, buf, nbytes, 0) == -1)
            {
                perror("client: send");
                close(serverfd);
                exit(1);
            }

            memset(&buf, 0, BUFLEN);
        }

        if (fds[1].revents & POLLIN)
        {
            nbytes = recv(fds[1].fd, buf, BUFLEN-1, 0);
            if (nbytes <= 0)
            {
                if (nbytes == 0)
                    puts("Server disconnected.");
                else
                    perror("client: recv");

                close(serverfd);
                exit(1);
            }

            buf[nbytes] = '\0';
            printf("%s", buf);
            fflush(stdout);
            memset(&buf, 0, BUFLEN);
        }
    }
}

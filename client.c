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

#include "const.h"


/* Gets the server file descriptor given the address in characters,
 * i.e. "192.168.0.15". Returns the serverfd on success, -1 otherwise. */
private int get_serverfd(char *address)
{
    int status, serverfd;
    struct addrinfo hints, *p, *serverinfo;
    char s[INET6_ADDRSTRLEN];

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    status = getaddrinfo(address, PORT, &hints, &serverinfo);
    if (status != 0)
    {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(status));
        return -1;
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
        fputs("get_serverfd: failed to connect\n", stderr);
        freeaddrinfo(serverinfo);
        return -1;
    }

    inet_ntop(p->ai_family, get_in_addr((struct sockaddr*)p->ai_addr),
            s, sizeof(s));
    printf("get_serverfd: connected to server %s.\n", s);

    freeaddrinfo(serverinfo);

    return serverfd;
}

/* Receives and checks if the username is within the valid length.
 *
 * Returns the length of the username string received on success, 
 * 0 on error or if any of the characters in there is not alphanumeric, 
 * or when the number of bytes received is less than MIN_USERNAME_LEN
 * or greater than uname_len. */
private int is_valid_username(char *username, int uname_len)
{
    int i, actual_len = 0;

    if (fgets(username, uname_len, stdin) == NULL)
    {
        return 0;
    }

    actual_len = strlen(username);
    if (actual_len < MIN_USERNAME_LEN)
    {
        fprintf(stderr, "Username cannot be less than %d characters.\n",
                MIN_USERNAME_LEN);
        return 0;
    }
    if (actual_len > uname_len)
    {
        fprintf(stderr, "Username cannot be greater than %d characters.\n",
                uname_len);
        return 0;
    }

    /* note: fgets reads the \n character on enter */
    for (i = 0; i < actual_len - 1; i++)
    {
        if (!isalnum(username[i]))
        {
            fprintf(stderr, "Username has to be alphanumeric.\n");
            return 0;
        }
    }

    return actual_len;
}

/* Keeps on prompting username until valid (see is_valid_username) and
 * null-terminates the username.
 *
 * Returns the number of bytes read including the null character.
 * */
private int get_username(char *username, int uname_len)
{
    int actual_len;

    printf("Please input your username (max %d characters): ", uname_len);
    while (!(actual_len = is_valid_username(username, uname_len)))
    {
        printf("Please input your username (max %d characters): ", uname_len);
    }
    /* Null-terminate username */
    term_str(username, actual_len, uname_len, CH_NULL);

    return actual_len;
}

/* Sends the username to serverfd.
 *
 * Returns 1 on error, 0 on success.
 * */
private int send_username(int serverfd)
{
    int uname_len;
    char username[USERNAME_LEN];

    while ((uname_len = get_username(username, USERNAME_LEN - 1)) <= 0);
    if (send(serverfd, username, uname_len, 0) == -1)
    {
        fprintf(stderr, "Could not send username to server.\n");
        perror("send");
        return 1;
    }
    return 0;
}

int main(int argc, char **argv)
{
    int serverfd, nbytes, npoll, buflen;
    char buf[BUFLEN];
    struct pollfd fds[2];

    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s hostname\n", argv[0]);
        exit(1);
    }

    if ((serverfd = get_serverfd(argv[1])) == -1)
    {
        exit(1);
    }
    
    fds[0].fd = STDIN_FILENO;
    fds[0].events = POLLIN;
    fds[0].revents = 0;

    fds[1].fd = serverfd;
    fds[1].events = POLLIN;
    fds[1].revents = 0;

    if (send_username(serverfd) != 0)
    {
        return 1;
    }

    buflen = sizeof(buf);
    for (;;)
    {
        npoll = poll(fds, 2, -1);
        if (npoll == -1)
        {
            perror("main: poll");
            close(serverfd);
            exit(1);
        }

        /* user send */
        if (fds[0].revents & POLLIN)
        {
            if (fgets(buf, BUFLEN, stdin) == NULL)
            {
                puts("Disconnecting...");
                close(serverfd);
                exit(0);
            }

            nbytes = strlen(buf);

            /* handle unintentional message */
            if (nbytes == 0 || iscntrl(buf[0]))
            {
                continue;
            }

            if (send(serverfd, buf, nbytes, 0) == -1)
            {
                perror("main: send");
                close(serverfd);
                exit(1);
            }
        }

        /* user receive */
        if (fds[1].revents & POLLIN)
        {
            nbytes = recv(fds[1].fd, buf, sizeof(buf)-1, 0);
            if (nbytes <= 0)
            {
                if (nbytes == 0)
                    puts("Server disconnected.");
                else
                    perror("main: recv");

                close(serverfd);
                exit(1);
            }

            term_str(buf, nbytes, buflen, CH_NEWLINE);
            printf("%s", buf);
            fflush(stdout);
        }

        memset(buf, 0, buflen);
    }
}

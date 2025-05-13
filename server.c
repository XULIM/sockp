#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <poll.h>
#include <errno.h>

#include "const.h"

typedef struct client Client;
struct client
{
    int fd;
    char name[USERNAME_LEN];
};

typedef struct pfds Ports;
struct pfds
{
    int cnt;
    int len;
    struct pollfd *fds;
    Client *users;
};

private struct pfds *pfds_init(int length)
{
    struct pfds *pf = (struct pfds*)malloc(sizeof(*pf));
    if (pf == NULL)
    {
        perror("pfds_init");
        exit(1);
    }
    pf->cnt = 0;
    pf->len = length;
    pf->fds = (struct pollfd*)malloc(length * sizeof(*pf->fds));
    if (pf->fds == NULL)
    {
        perror("pfds_init (struct pollfd)");
        exit(1);
    }
    pf->users = (Client*)malloc(length * sizeof(*pf->users));

    return pf;
}

private void pfds_free(struct pfds *pf)
{
    free(pf->fds);
    free(pf->users);
    free(pf);
}

private void pfds_add(struct pfds *pf, int sockfd, int events,
        char *username, int username_len)
{
    struct pollfd *tmp_fds;
    Client *tmp_cl;

    if (pf->cnt == pf->len)
    {
        pf->len *= 2;
        tmp_fds = realloc(pf->fds, pf->len * sizeof(*pf->fds));
        tmp_cl = realloc(pf->users, pf->len * sizeof(*pf->users));
        if (tmp_fds == NULL)
        {
            perror("pfds_add (fds)");
            exit(1);
        }
        if (tmp_cl == NULL)
        {
            perror("pfds_add (users)");
        }
        pf->fds = tmp_fds;
        pf->users = tmp_cl;
    }

    strlcpy(pf->users[pf->cnt].name, username, username_len);
    pf->users[pf->cnt].fd = sockfd;
    pf->fds[pf->cnt].fd = sockfd;
    pf->fds[pf->cnt].events = events;
    pf->fds[pf->cnt].revents = 0;

    pf->cnt++;
}

private void pfds_del(struct pfds *pf, int index)
{
    pf->cnt--;
    pf->fds[index] = pf->fds[pf->cnt];
    pf->users[index] = pf->users[pf->cnt];
}

/*
private void pfds_print(struct pfds *pf)
{
    printf("pfds len: %d\n", pf->len);
    printf("pfds cnt: %d\n", pf->cnt);
    for (int i = 0; i < pf->cnt; i++)
    {
        printf("fd %d --\n", i);
        printf("%*susername: %s\n", 4, " ", pf->users[i].name);
        printf("%*slistener socket: %d\n", 4, " ", pf->fds[i].fd);
        printf("%*slistener events: %d\n", 4, " ", pf->fds[i].events);
    }
}
*/

private int get_listener_sock()
{
    int listener, status, yes=1;
    struct addrinfo hints, *p, *res;
    
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;

    status = getaddrinfo(NULL, PORT, &hints, &res);
    if (status == -1)
    {
        fprintf(stderr, "server: %s\n", gai_strerror(status));
        exit(1);
    }

    for (p = res; p != NULL; p = p->ai_next)
    {
        listener = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (listener < 0)
        {
            perror("server (socket)");
            continue;
        }

        if (setsockopt(listener, SOL_SOCKET, SO_REUSEADDR,
                    &yes, sizeof(int)) == -1)
        {
            perror("server (setsockopt)");
        }

        if (bind(listener, p->ai_addr, p->ai_addrlen) == -1)
        {
            close(listener);
            perror("server (bind)");
            continue;
        }
        
        break;
    }

    freeaddrinfo(res);

    if (p == NULL)
    {
        return -1;
    }

    if (listen(listener, BACKLOG) == -1)
    {
        close(listener);
        return -1;
    }

    return listener;
}

private void broadcast_join(struct pfds *pf, int listener, int newfd, char *username)
{
    int i, destfd;
    char msg[BUFLEN];

    snprintf(msg, BUFLEN, "%s joined.", username);
    for (i = 0; i < pf->cnt; i++)
    {
        destfd = pf->fds[i].fd;
        if (destfd != listener && destfd != newfd)
        {
            if (send(destfd, msg, BUFLEN, 0) == -1)
            {
                perror("broadcast_join (send)");
            }
        }
    }
}

/* Receives the username on sockfd.
 * Returns 0 on failure, and username is set to ("Anonymous %d", sockfd).
 * Otherwise, return the number of bytes received. */
private int recv_username(int sockfd, char *username, int uname_len)
{
    int nbytes;

    nbytes = recv(sockfd, username, uname_len, 0);
    if (nbytes == -1 || (nbytes == 1 && iscntrl(username[0])))
    {
        snprintf(username, uname_len, "Anonymous %d", sockfd);
        return 0;
    }

    return nbytes;
}

private void handle_new_connection(struct pfds *pf, int listener)
{
    int sockfd, nbytes;
    socklen_t addrlen;
    struct sockaddr_storage addr;
    char ip[INET6_ADDRSTRLEN], username[USERNAME_LEN];
    
    addrlen = sizeof(addr);
    sockfd = accept(listener, (struct sockaddr*)&addr, &addrlen);
    if (sockfd == -1)
    {
        perror("server (accept)");
        return;
    }

    if (inet_ntop(addr.ss_family, get_in_addr((struct sockaddr*)&addr),
                ip, sizeof(ip)) == NULL)
    {
        fprintf(stderr, "inet_ntop error - %s\n", strerror(errno));
        close(sockfd);
        return;
    }

    nbytes = recv_username(sockfd, username, USERNAME_LEN);
    if (nbytes == 0)
    {
        perror("recv");
    }
    /* Null-terminate username */
    term_str(username, nbytes, USERNAME_LEN, CH_NULL);

    pfds_add(pf, sockfd, POLLIN, username, nbytes);
    printf("User %s connected on socket %d as %s.\n", ip, sockfd, username);
    broadcast_join(pf, listener, sockfd, username);

}

/* Receives a string from the user on the socket indicated by pf->fds[*idx].fd
 * and writes it to buf.
 *
 * Returns the number of bytes received on success; -1 if it exceeds buflen; 0
 * if the number of bytes received is less than or equal to 0. */
private int recv_msg(struct pfds *pf, int *idx, char *buf, size_t buflen)
{
    int sendfd;
    int nbytes;

    sendfd = pf->fds[*idx].fd;
    nbytes = recv(sendfd, buf, buflen, 0);
    if (nbytes <= 0)
    {
        if (nbytes == 0)
        {
            fprintf(stderr, "recv_msg: user %s on socket %d hung up.\n",
                    pf->users[*idx].name, sendfd);
        }
        else
        {
            perror("server (recv)");
        }

        close(sendfd);
        pfds_del(pf, *idx);
        (*idx)--;
        return 0;
    }

    /* msg buf check */
    if (nbytes > (int)buflen)
    {
        fprintf(stderr,
                "recv_msg: user message cannot be longer than %lu characters.\n",
                buflen);
        return -1;
    }

    /* TODO: handle series of spaces */

    term_str(buf, nbytes, buflen, CH_NEWLINE);

    return nbytes;
}

/* Sends buf of buflen to all sockets in pf, excluding the listener and self,
 * which indicated by idx. */
private void broadcast(struct pfds *pf, int listener, int *idx, char *buf, size_t buflen)
{
    int i, destfd;

    for (i = 0; i < pf->cnt; i++)
    {
        destfd = pf->fds[i].fd;
        if (destfd != listener && destfd != pf->fds[*idx].fd)
        {
            if (send(destfd, buf, buflen, 0) == -1)
            {
                perror("server (send)");
            }
        }
    }
}

int main(void)
{
    int listener, pollcnt, nbytes, i;
    char buf[BUFLEN];
    struct pfds *pf;

    listener = get_listener_sock();
    if (listener == -1)
    {
        fputs("main: error getting listener socket", stderr);
        exit(1);
    }
    pf = pfds_init(PFDS_INIT_LEN);
    pfds_add(pf, listener, POLLIN, "SERVER", 6);

    for (;;)
    {
        pollcnt = poll(pf->fds, pf->cnt, -1);
        if (pollcnt < 0)
        {
            perror("server (poll)");
            pfds_free(pf);
            exit(1);
        }
        
        /* reading available data from sockets */
        for (i = 0; i < pf->cnt; i++)
        {
            if (!(pf->fds[i].revents & (POLLIN | POLLHUP)))
            {
                continue;
            }

            if (pf->fds[i].fd == listener)
            {
                handle_new_connection(pf, listener);
                continue;
            }

            nbytes = recv_msg(pf, &i, buf, sizeof(buf)-1);
            if (nbytes == 0)
                continue;
            else if (nbytes < 0)
                exit(1);

            broadcast(pf, listener, &i, buf, nbytes);
            memset(buf, CH_NULL, sizeof(buf));
        }
    }
}

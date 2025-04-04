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

#define PORT "6969"

enum
{
    BUFLEN = 256,
    BACKLOG = 10,
    PFDS_INIT_LEN = 5,
    USERNAME_LEN = 32,
};

struct pfds
{
    int cnt;
    int len;
    struct pollfd *fds;
};

struct pfds *pfds_init(int length)
{
    struct pfds *pf = (struct pfds*)malloc(sizeof(struct pfds));
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

    return pf;
}

void pfds_free(struct pfds *pf)
{
    free(pf->fds);
    free(pf);
}

void pfds_add(struct pfds *pf, int sockfd, int events)
{
    struct pollfd *temp;

    if (pf->cnt == pf->len)
    {
        pf->len *= 2;
        temp = realloc(pf->fds, pf->len * sizeof(*pf->fds));
        if (temp == NULL)
        {
            perror("pfds_add (realloc)");
            exit(1);
        }
        pf->fds = temp;
    }

    pf->fds[pf->cnt].fd = sockfd;
    pf->fds[pf->cnt].events = events;
    pf->fds[pf->cnt].revents = 0;
    pf->cnt++;
}

void pfds_del(struct pfds *pf, int index)
{
    pf->cnt--;
    pf->fds[index] = pf->fds[pf->cnt];
}

void pfds_print(struct pfds *pf)
{
    printf("pfds len: %d\n", pf->len);
    printf("pfds cnt: %d\n", pf->cnt);
    for (int i = 0; i < pf->cnt; i++)
    {
        printf("fd %d --\n", i);
        printf("%*slistener socket: %d\n", 4, " ", pf->fds[i].fd);
        printf("%*slistener events: %d\n", 4, " ", pf->fds[i].events);
    }
}

void *get_in_addr(struct sockaddr *s)
{
    if (s->sa_family == AF_INET)
    {
        return &(((struct sockaddr_in*)s)->sin_addr);
    }
    return &(((struct sockaddr_in6*)s)->sin6_addr);
}

int get_listener_sock()
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

void handle_new_connection(struct pfds *pf, int listener)
{
    int sockfd;
    socklen_t addrlen;
    struct sockaddr_storage addr;
    char ip[INET6_ADDRSTRLEN];
    
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
        fprintf(stderr, "server: inet_ntop error - %s\n", strerror(errno));
        close(sockfd);
        return;
    }

    pfds_add(pf, sockfd, POLLIN);
    printf("server: accepted connection from %s on socket %d\n", ip, sockfd);
}

void broadcast(struct pfds *pf, int listener, int sendfd, char *buf, size_t buflen)
{
    int i, destfd;

    for (int i = 0; i < pf->cnt; i++)
    {
        destfd = pf->fds[i].fd;
        if (destfd != listener && destfd != sendfd)
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
    int listener, pollcnt, nbytes, sendfd, i;
    char buf[BUFLEN];
    struct pfds *pf;

    listener = get_listener_sock();
    if (listener == -1)
    {
        fputs("server: error getting listener socket", stderr);
        exit(1);
    }
    pf = pfds_init(PFDS_INIT_LEN);
    pfds_add(pf, listener, POLLIN);

    for (;;)
    {
        pollcnt = poll(pf->fds, pf->cnt, -1);
        if (pollcnt < 0)
        {
            perror("server (poll)");
            pfds_free(pf);
            exit(1);
        }
        
        // reading available data from sockets
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

            /* regular client */
            sendfd = pf->fds[i].fd;
            nbytes = recv(sendfd, buf, sizeof(buf)-1, 0);
            if (nbytes <= 0)
            {
                if (nbytes == 0)
                {
                    printf("server: socket %d hung up\n", sendfd);
                }
                else perror("server (recv)");

                close(pf->fds[i].fd);
                pfds_del(pf, i);
                i--;
                continue;
            }
            if (buf[nbytes-1] != '\n')
            {
                buf[nbytes] = '\n';
                nbytes++;
            }
            broadcast(pf, listener, sendfd, buf, nbytes);
        }
    }
}

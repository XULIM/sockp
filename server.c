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

typedef struct client
{
    int fd;
    char name[USERNAME_LEN];
} Client;

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

private void pfds_add(struct pfds *pf, int sockfd, int events, char username[])
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

    pf->fds[pf->cnt].fd = sockfd;
    pf->fds[pf->cnt].events = events;
    pf->fds[pf->cnt].revents = 0;

    /* TODO: check users */
    pf->users[pf->cnt].fd = sockfd;
    strcpy(pf->users[pf->cnt].name, username);

    pf->cnt++;
}

private void pfds_del(struct pfds *pf, int index)
{
    pf->cnt--;
    pf->fds[index] = pf->fds[pf->cnt];
    pf->users[index] = pf->users[pf->cnt];
}

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

private void broadcast_join(struct pfds *pf, int listener, int newfd, const char *username)
{
    int i, destfd;
    char msg[BUFLEN];
    snprintf(msg, sizeof(msg), "%s has joined the chat.\n", username);

    for (i = 0; i < pf->cnt; i++)
    {
        destfd = pf->fds[i].fd;
        if (destfd != listener && destfd != newfd)
        {
            if (send(destfd, msg, strlen(msg), 0) == -1)
            {
                perror("broadcast_join (send)");
            }
        }
    }
}

/* not used right now
private int get_new_username(int sockfd, char *username, size_t username_len)
{
    struct timeval tv;
    int nbytes;
    size_t prompt_len, uname_err_len;
    const char *prompt = "Enter your username: ";
    const char *uname_err = "Username can be longer than 32 characters.";
    
    prompt_len = strlen(prompt);
    uname_err_len = strlen(uname_err);
    tv.tv_sec = 10;
    tv.tv_usec = 0;
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    if (send(sockfd, prompt, prompt_len, 0) == -1)
    {
        perror("Failed prompting username (send)");
        close(sockfd);
        return -1;
    }


    nbytes = recv(sockfd, username, username_len, 0);
    if (nbytes == -1)
    {
        if (errno == EAGAIN)
        {
            fprintf(stderr, "User on socket %d timed out.\n", sockfd);
        }
        else perror("Failed to get username (recv)");

        close(sockfd);
        return 0;
    }
    else if (nbytes == 0)
    {
        fprintf(stderr, "User on socket %d hung up.\n", sockfd);
        close(sockfd);
        return 0;
    }

    // TODO: possibly null-terminate username 

    return (nbytes > USERNAME_LEN ? USERNAME_LEN : nbytes);
}
*/

private void handle_new_connection(struct pfds *pf, int listener)
{
    int sockfd, prompt_len, nbytes;
    socklen_t addrlen;
    struct sockaddr_storage addr;
    struct timeval tv;
    char ip[INET6_ADDRSTRLEN], username[USERNAME_LEN];
    const char *prompt = "Enter your username: ";

    prompt_len = strlen(prompt);
    
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

    /* prompt for username */
    if (send(sockfd, prompt, prompt_len, 0) == -1)
    {
        perror("send");
        close(sockfd);
        return;
    }

    tv.tv_sec = 10; // 10 sec timeout
    tv.tv_usec = 0;
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    nbytes = recv(sockfd, &username, sizeof(username)-1, 0);
    if (nbytes == -1 && errno == EAGAIN)
    {
        fprintf(stderr, "User timed out on socket %d.\n", sockfd);
        close(sockfd);
        return;
    }
    else if (nbytes == 0)
    {
        fputs("User disconnected.\n", stderr);
        close(sockfd);
        return;
    }
    
    username[nbytes] = '\0';
    if (username[nbytes - 1] == '\n')
        username[nbytes - 1] = '\0';
    /* END username prompt */

    pfds_add(pf, sockfd, POLLIN, username);
    printf("server: accepted connection from %s on socket %d\n", ip, sockfd);
    broadcast_join(pf, listener, sockfd, username);

}

/* TODO: finish bufcpy (secure strcpy), copies str with a length of no greater
 * than MAX_BUFLEN and dynamically resizes the buf if needed */
void bufcpy(char *str, int strlen, char *buf, int buflen);

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
            fprintf(stderr, "Client on socket %d hung up.\n", sendfd);
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
    if (nbytes > MAX_BUFLEN)
    {
        fprintf(stderr,
                "recv_msg: user message cannot be longer than %d characters.\n",
                MAX_BUFLEN);
        return -1;
    }

    /* append newline to end of buffer */
    if (buf[nbytes-1] != '\n')
    {
        buf[nbytes] = '\n';
        nbytes++;
    }

    return nbytes;
}

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
        fputs("server: error getting listener socket", stderr);
        exit(1);
    }
    pf = pfds_init(PFDS_INIT_LEN);
    pfds_add(pf, listener, POLLIN, "SERVER");

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
        }
    }
}

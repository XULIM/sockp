#ifndef CONST_H
#define CONST_H

#define private static

#define PORT "6969"
enum
{
    BUFLEN = 255,
    MAX_BUFLEN = 512,
    BACKLOG = 10,
    PFDS_INIT_LEN = 5,
    USERNAME_LEN = 32,
};

static inline void *get_in_addr(struct sockaddr *s)
{
    if (s->sa_family == AF_INET)
    {
        return &(((struct sockaddr_in*)s)->sin_addr);
    }
    return &(((struct sockaddr_in6*)s)->sin6_addr);
}

#endif

#ifndef CONST_H
#define CONST_H

#include <ctype.h>

#define private static
#define PORT "6969"

enum
{
    BUFLEN = 255,
    MAX_BUFLEN = 512,
    BACKLOG = 10,
    PFDS_INIT_LEN = 5,
    MIN_USERNAME_LEN = 4,
    USERNAME_LEN = 32,
    CH_NEWLINE = '\n',
    CH_NULL = '\0'
};

/* Typecasts struct sockaddr to their respective family (IPv4 or IPv6) and
 * returns the address struct.
 *
 * Returns struct in_addr containing the address for IPv4 addresses, and
 * struct in6_addr for IPv6 adresses.
 * */
static inline void* get_in_addr(struct sockaddr *s)
{
    if (s->sa_family == AF_INET)
    {
        return &(((struct sockaddr_in*)s)->sin_addr);
    }
    return &(((struct sockaddr_in6*)s)->sin6_addr);
}

/* Terminates str with termch.
 * Paramters:
 * - str: the string to be terminated.
 * - strlen: the actual size of str.
 * - maxlen: the max length of str.
 * - termch: the terminal character.
 **/
static inline void term_str(char *str, int strlen, int maxlen, char termch)
{
    if (iscntrl(str[strlen-1]) || strlen == maxlen)
    {
        str[strlen-1] = termch;
    }
    else
    {
        str[strlen] = termch;
    }
}

#endif

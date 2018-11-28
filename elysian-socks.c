#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>

#include "elysian-socks.h"

void elysian_socks_init(elysian_socks_t *es){
    memset(es, 0x0, sizeof(elysian_socks_t));
}

void elysian_socks_setopt(elysian_socks_t *es, int opt, ...){
    va_list args;
    va_start(args, opt);

    switch(opt){
        case ES_CONNECTION:
            es->conn = va_arg(args, int);
        break;

        case ES_IPV4:
        case ES_IPV6:
        case ES_HOSTNAME:
            es->addr = va_arg(args, void *);
            es->addrtype = opt;
        break;

        case ES_PORT:
            es->port = htons(va_arg(args, int));
        break;

        case ES_AUTHTYPE:
            if(es->nmethods < 255){
                es->methods[es->nmethods] = va_arg(args, int);
                es->nmethods++;
            }
        break;

        case ES_AUTHCALLBACK:
            es->auth_callback = va_arg(args, es_auth_callback);
        break;

        case ES_AUTHDATA:
            es->authdata = va_arg(args, void *);
        break;
    }

    va_end(args);
}

int elysian_socks_auth(elysian_socks_t *es){
    int ret = 1;
    ssize_t len = 0;
    unsigned char response[4];
    char *buf;

    len = es->nmethods+2;
    buf = malloc(len);

    /* version */
    buf[0] = 0x5;

    /* number of auth methods */
    buf[1] = es->nmethods;

    /* set auth methods */
    memcpy(buf+2, es->methods, es->nmethods);

    if(send(es->conn, buf, len, MSG_NOSIGNAL) != len)
        goto end;

    if(recv(es->conn, response, 3, MSG_NOSIGNAL) != 2)
        goto end;

    /* check version number */
    if(response[0] != 5)
        goto end;

    /* auth method not supported */
    if(response[1] == 0xff)
        goto end;

    /* authenticate */
    if(response[1]){
        if(!es->auth_callback ||
            !es->auth_callback(es->conn, response[1], es->authdata))
        goto end;
    }

    ret = 0;

    end:
    free(buf);
    return ret;
}

int elysian_socks_connect(elysian_socks_t *es){
    char *aux, *buf, response[5], *dest_addr;
    size_t len = 6, addrlen = 0;
    int ret = 1;

    switch(es->addrtype){
        case ES_IPV4:
            addrlen = sizeof(struct in_addr);
            len += addrlen;
        break;
        case ES_IPV6:
            addrlen = sizeof(struct in6_addr);
            len += addrlen;
        break;
        case ES_HOSTNAME:
            addrlen = strlen(es->addr);
            len += addrlen+1;
        break;
        default:
            goto end;
    }

    aux = buf = malloc(len);

    /* version */
    *buf++ = 0x05;

    /* connect */
    *buf++ = 0x1;

    /* reserved */
    *buf++ = 0x0;

    /* self-explanatory, no ? */
    *buf++ = es->addrtype;

    /* set hostname length */
    if(es->addrtype == ES_HOSTNAME)
        *buf++ = addrlen;

    /* set address */
    memcpy(buf, es->addr, addrlen);

    /* set port */
    memcpy(buf+addrlen, &(es->port), 2);

    if(send(es->conn, aux, len, MSG_NOSIGNAL) != (ssize_t)len)
        goto end;

    if(recv(es->conn, response, 4, MSG_NOSIGNAL) != 4)
        goto end;

    /* check version and status */
    if(response[0] != 5 || response[1] != 0)
        goto end;

    /* get address type */
    switch(response[3]){
        case 0x1:
            len = sizeof(struct in_addr)+2;
            dest_addr = malloc(len);
        break;
        case 0x4:
            len = sizeof(struct in6_addr)+2;
            dest_addr = malloc(len);
        break;
        default:
            goto end;
    }

    if(recv(es->conn, dest_addr, len, MSG_NOSIGNAL) != (ssize_t)len){
        free(dest_addr);
        goto end;
    }

    es->raddrtype = response[3];
    es->raddr = dest_addr;
    es->rport = *(unsigned short *)(dest_addr+len-2);

    ret = 0;

    end:
    free(aux);
    return ret;
}

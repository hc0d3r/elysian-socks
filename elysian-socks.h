#ifndef __ELYSIAN_H__
#define __ELYSIAN_H__

typedef int(*es_auth_callback)(int, int, void *);

typedef struct elysian_socks {
    int conn;

    void *addr;
    int addrtype;

    es_auth_callback auth_callback;
    void *authdata;

    unsigned short port;
    char methods[255];
    int nmethods;

    int errcode;

    int raddrtype;
    void *raddr;
    unsigned short rport;

    int connection_timeout;
    int auth_timeout;
} elysian_socks_t;

enum {
    ES_CONNECTION,
    ES_IPV4,
    ES_PORT,
    ES_HOSTNAME,
    ES_IPV6,
    ES_AUTHTYPE,
    ES_AUTHCALLBACK,
    ES_AUTHDATA,
    ES_CONNECTION_TIMEOUT,
    ES_AUTH_TIMEOUT
};

void elysian_socks_init(elysian_socks_t *es);

void elysian_socks_setopt(elysian_socks_t *es, int opt, ...);

int elysian_socks_auth(elysian_socks_t *es);
int elysian_socks_connect(elysian_socks_t *es);

#endif

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "elysian-socks.h"

#define IP "127.0.0.1"
#define PORT 9050

#define failcheck(var, msg) do { \
    if(var == -1){ \
        perror(msg); \
        exit(1); \
    } \
} while(0)

#define expsize(x) x, sizeof(x)-1

int main(void){
    struct sockaddr_in addr;
    struct in6_addr ipv6;

    elysian_socks_t es;
    int status, fd, n;
    char buf[1024];

    fd = socket(AF_INET, SOCK_STREAM, 0);
    failcheck(fd, "socket");

    addr.sin_family = AF_INET;
    addr.sin_port = htons(PORT);
    addr.sin_addr.s_addr = inet_addr(IP);

    status = connect(fd, (struct sockaddr *)&addr, sizeof(addr));
    failcheck(status, "connect");

    inet_pton(AF_INET6, "2800:3f0:4004:809::200e", &ipv6);

    elysian_socks_init(&es);

    elysian_socks_setopt(&es, ES_CONNECTION, fd);
    elysian_socks_setopt(&es, ES_IPV6, &ipv6);
    elysian_socks_setopt(&es, ES_PORT, 80);
    elysian_socks_setopt(&es, ES_AUTHTYPE, 0x0);
    elysian_socks_setopt(&es, ES_AUTH_TIMEOUT, 5);

    setvbuf(stdout, NULL, _IONBF, 0);

    printf("authenticating... ");
    if(elysian_socks_auth(&es)){
        printf("error\n");
        exit(1);
    }
    printf("ok\n");

    printf("connecting... ");
    if(elysian_socks_connect(&es)){
        printf("error\n");
    }

    printf("ok\n");

    write(fd, expsize("HEAD / HTTP/1.1\r\nConnection: close\r\n\r\n"));

    while((n = read(fd, buf, sizeof(buf))) > 0)
        write(1, buf, n);

    close(fd);

    return 0;
}

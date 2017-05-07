/* Simplified Unix Networking Library for CpS 320
 * (c) 2016, Bob Jones University
 */
#include <stdio.h>
#include <string.h>
#include <errno.h>

#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#include "eznet.h"

int create_tcp_server(const char *bindhost, const char *bindport) {
    int ret = -1, sock = -1, status;

    // Set up our "hints" for TCP (SOCK_STREAM) over IPv4
    struct addrinfo hints = {
        .ai_family = AF_INET,
        .ai_socktype = SOCK_STREAM,
        .ai_protocol = IPPROTO_TCP,
    };

    // Look up host name/address info for bindhost:bindport...
    struct addrinfo *ai_list = NULL;
    if ((status = getaddrinfo(bindhost, bindport, &hints, &ai_list)) != 0) {
        LOG_ERROR("getaddrinfo('%s', '%s'...) -> '%s'", bindhost, bindport, gai_strerror(status));
        goto cleanup;
    }

    // Walk any/all socket addresses returned, trying to create/bind on them in turn...
    for (struct addrinfo *ai_iter = ai_list; ai_iter; ai_iter = ai_iter->ai_next) {
        // Try to create a socket...
        sock = socket(ai_iter->ai_family, ai_iter->ai_socktype, ai_iter->ai_protocol);
        if (sock < 0) {
            LOG_ERROR("socket(...) -> '%s'", strerror(errno));
            continue;   // Try next ai_info entry
        }
        
        // Try to bind
        if (bind(sock, ai_iter->ai_addr, ai_iter->ai_addrlen)) {
            LOG_ERROR("bind(...) -> '%s'", strerror(errno));
            close(sock);
            sock = -1;
            continue;   // Try next (after closing this one)
        } 

        // Try listen
        if (listen(sock, 5)) {
            LOG_ERROR("listen(...) -> '%s'", strerror(errno));
            close(sock);
            sock = -1;
            continue;   // And again...
        }

        // Everything worked! Set up to return this puppy!
        ret = sock;
        sock = -1;      // So cleanup routine doesn't close our socket on us
        goto cleanup;
    }

cleanup:
    if (sock >= 0) close(sock);
    freeaddrinfo(ai_list);
    return ret;
}

int wait_for_client(int server_sock, struct client_info *ci) {
    int ret = -1, client_sock = -1;

    // accept() the next connection coming in on server_sock...
    struct sockaddr_in sa = { 0 };
    socklen_t slen = sizeof(sa);
    client_sock = accept(server_sock, (struct sockaddr *)&sa, &slen);
    if (client_sock < 0) {
        LOG_ERROR("accept(%d, ...) -> '%s'", server_sock, strerror(errno));
        goto cleanup;
    }

    // Verify that family is correct (i.e., IPv4 only)
    if (sa.sin_family != AF_INET) {
        LOG_ERROR("FD %d is not an AF_INET (IPv4) socket!", server_sock);
        goto cleanup;
    }

    // Extract IP address into C-string
    if (inet_ntop(sa.sin_family, &sa.sin_addr, ci->ip, INET_ADDRSTRLEN) == NULL) {
        LOG_ERROR("inet_ntop(...) -> '%s'", strerror(errno));
        goto cleanup;
    }

    // Finish shipping out the data 
    ci->port = ntohs(sa.sin_port);
    ci->fd = client_sock;

    // "Release" ownership of client socket fd    
    client_sock = -1;       

    // Return success
    ret = 0;
cleanup:
    if (client_sock >= 0) close(client_sock);
    return ret;
}

void destroy_client_info(struct client_info *ci) {
    if (ci->fd >= 0) { close(ci->fd); }
    memset(ci, 0, sizeof(*ci));
}


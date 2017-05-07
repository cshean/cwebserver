/* Simplified Unix Networking Library for CpS 320
 * (c) 2016, Bob Jones University
 */
#ifndef BJU_CPS320_EZNET_H
#define BJU_CPS320_EZNET_H

// Needed for the constant INET_ADDRSTRLEN
#include <arpa/inet.h>

// Debug error logging macro (for logging unlikely errors)
// Intended primarily for internal use by eznet, but published
// in this header file since it may be useful to eznet users.
#ifdef SHOW_LOG_ERROR
#   define LOG_ERROR(FmtStrLiteral, ...) \
        fprintf(stderr, "%s:%d:" FmtStrLiteral "\n", __FILE__, __LINE__, __VA_ARGS__)
#else
    // Compiles away to nothing unless SHOW_LOG_ERROR is defined
#   define LOG_ERROR(FmtStrLiteral, ...)
#endif

// "Connected client socket object" structure
struct client_info {
    int fd;                     // Socket file descriptor
    char ip[INET_ADDRSTRLEN+1]; // Socket name (IP address in text form)
    int port;                   // Socket name (port number)
}; 

// Create a TCP/IPv4 socket and bind it to the endpoint described
// by <bindhost>:<bindport>.  On success, returns a file descriptor
// >= 0 which describes a listening TCP server socket;
// on failure, returns -1.
int create_tcp_server(const char *bindhost, const char *bindport);

// accept() a connection on a listening socket <server_sock>.
// On success, populates <ci> with the file descriptor describing
// the new connection socket (along with endpoint address/port information)
// and returns 0; on failure, returns -1.
int wait_for_client(int server_sock, struct client_info *ci);

// Close the socket described by <ci>'s ->fd field and
// zeros out the structure pointed to by <ci>.
void destroy_client_info(struct client_info *ci);


#endif


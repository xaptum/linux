/**
 * @file f_psock_socket.h
 * @brief Public functions fot the socket part of the psock module
 */

#include <net/sock.h>
#include "f_psock_proxy.h"

#ifndef _F_PSOCK_SOCKET_H_
#define _F_PSOCK_SOCKET_H_

/**
 * Initialize the psock_socket part
 */
int f_psock_init_sockets( void );

/**
 * Cleanup the psock_socket part
 */
int f_psock_cleanup_sockets( void );


/**
 * psock local socket data
 */
struct f_psock_pinfo
{
	struct sock		sk; 	 /**< @note Needs to be here as first entry !! */
	struct f_psock_proxy_socket psk; /**< our local socket information */
};

#endif // _F_PSOCK_SOCKET_H_


/**
 * @file xaprc00x_socket.c
 * @brief Create the psock socket type
 *  This creates a new socket type for proxying to the connected host device
 *  This part of the module communicates with the psock_proxy part
 * @author Jeroen Z
 */

#include <linux/module.h>
#include <linux/net.h>
#include <net/sock.h>
#include <linux/xscm.h>
#define PSOCK_SK_BUFF_SIZE 512
#define PSOCK_SK_SND_TIMEO 1000

/* Extern proxy defs */
extern void scm_proxy_close_socket(int local_id);
extern int scm_proxy_open_socket(int *local_id);
extern int scm_proxy_connect_socket(int local_id, struct sockaddr *addr, int alen);
extern void scm_proxy_wait_ack(struct scm_packet **packet, int msg_id);

/**
 * psock local socket data
 */
struct xaprc00x_pinfo
{
	struct sock		sk; 	 /**< @note Needs to be here as first entry !! */
	int			local_id;
};

/**
 * kill the socket
 * Sets flag for removal
 */
static void xaprc00x_sock_kill(struct sock *sk )
{
	sock_set_flag(sk, SOCK_DEAD);
	sock_put(sk);
}

/**
 * Function called for socket shutdown
 */
static int xaprc00x_sock_shutdown(struct socket *sock, int how )
{
	struct sock *sk = sock->sk;
        struct xaprc00x_pinfo *psk = (struct xaprc00x_pinfo *)sk;
	
	if (!sk)
	{
		return 0;
	}

	if (!sk->sk_shutdown) 
	{
		sk->sk_shutdown = SHUTDOWN_MASK;
	}

	//printk( KERN_INFO "xaprc00x_socket : socket shutdown :%d\n", psk->local_id );

        scm_proxy_close_socket( psk->local_id );

	release_sock(sk);

	return 0;	
}


/**
 * Function called when releasing a socket
 */
static int xaprc00x_sock_release(struct socket *sock)
{
	struct sock *sk = sock->sk;
	int err;
	//printk( KERN_INFO "xaprc00x_socket : releasing socket\n" );

	if ( !sk ) 
	{
		return 0;
	}

	err = xaprc00x_sock_shutdown(sock, 2 );

	sock_orphan(sk);

	xaprc00x_sock_kill(sk);

	return err;
}

/**
 * Function for connecting a socket
 */
static int xaprc00x_sock_connect(struct socket *sock, struct sockaddr *addr, int alen, int flags )
{	
	int ret;
	struct xaprc00x_pinfo *psk = (struct xaprc00x_pinfo *)sock->sk;

	//printk( KERN_INFO "psock_socket : Connecting socket : %d\n", psk->local_id );

	ret = scm_proxy_connect_socket(psk->local_id, addr, alen);
	return ret;
}

/**
 * Function for getname
 */
/*
static int xaprc00x_sock_getname(struct socket *sock, struct sockaddr *addr, int peer )
{
	printk( KERN_INFO "psock getname\n" );
	return 0;
}
*/

/**
 * Function for sending a msg over the socket
 */
static int xaprc00x_sock_sendmsg( struct socket *sock,
				 struct msghdr *msg, size_t len )
{
	int res, r;
	void *data = kmalloc( len, GFP_KERNEL );
	struct xaprc00x_pinfo *psk = (struct xaprc00x_pinfo *)sock->sk;

	//printk( KERN_INFO "scm sendmsg not supported %d\n", psk->local_id );

	return 0;
}

/**
 * Function for recv msg from the socket
 */
static int xaprc00x_sock_recvmsg(struct socket *sock,
				struct msghdr *msg, size_t size, int flags )
{
	struct xaprc00x_pinfo *psk = (struct xaprc00x_pinfo *)sock->sk;
	char *buf = kmalloc( size, GFP_KERNEL );

	//printk( KERN_INFO "scm recv not supported %d\n", psk->local_id );

	kfree( buf );

	return 0;
}


/**
 * Bind an address to the socket
 */
static int xaprc00x_sock_bind(struct socket *sock, struct sockaddr *addr, int addr_len)
{
	printk( KERN_INFO "xaprc00x_socket : bind not supported on psock socket\n" );
	return 0;
}

/**
 * Operation definitions for the psock type
 */
static const struct proto_ops xaprc00x_ops =
{
	.family		= PF_PSOCK,
	.owner		= THIS_MODULE,
	.release	= xaprc00x_sock_release,
	.bind		= xaprc00x_sock_bind,
	.connect	= xaprc00x_sock_connect,
	.listen		= NULL,
	.accept		= NULL,
	.getname 	= NULL, // xaprc00x_sock_getname,
	.sendmsg	= xaprc00x_sock_sendmsg,
	.recvmsg	= xaprc00x_sock_recvmsg,
	.shutdown	= xaprc00x_sock_shutdown,
	.setsockopt	= NULL,
	.getsockopt	= NULL,
	.ioctl		= NULL,
	.poll		= NULL,
	.socketpair 	= sock_no_socketpair,
	.mmap		= sock_no_mmap

};

/**
 * PSOCK proto definition
 */
static struct proto xaprc00x_proto =
{
	.name = "SCM",
	.owner = THIS_MODULE,
	.obj_size = sizeof( struct xaprc00x_pinfo )
};

/**
 * Socket destruction
 */
static void xaprc00x_sock_destruct(struct sock *sk)
{
//	skb_queue_purge(&sk->sk_receive_queue);
//	skb_queue_purge(&sk->sk_write_queue);
}

/**
 * Allocate socket data
 */
static struct sock *scm_sock_alloc(struct net *net, struct socket *sock, int proto, gfp_t prio, int kern)
{
	struct sock *sk;

	printk( KERN_INFO "psock_socket: Allocating sk socket\n" );
	sk = sk_alloc(net, PF_PSOCK, prio, &xaprc00x_proto , kern);

	if ( !sk )
	{
		printk( KERN_ERR "psock_socket: Error allocating sk socket\n" );
		goto exit;
	}
	
	sock_init_data(sock, sk);

	sk->sk_destruct = xaprc00x_sock_destruct;
	sk->sk_sndtimeo = PSOCK_SK_SND_TIMEO;
	sk->sk_sndbuf = PSOCK_SK_BUFF_SIZE;
	sk->sk_rcvbuf = PSOCK_SK_BUFF_SIZE;

	sock_reset_flag(sk, SOCK_ZAPPED);

	sk->sk_protocol = proto;
//	sk->sk_state = BT_OPEN;
exit:
	return sk;
}

/**
 *  Create a socket for the psock type 
 */
static int scm_sock_create(struct net *net, struct socket *sock, int protocol, int kern)
{
	struct sock *sk;
	struct xaprc00x_pinfo *psk;
	int ret;

	sock->state = SS_UNCONNECTED;
	sock->ops = &xaprc00x_ops;

	sk = scm_sock_alloc(net, sock, protocol, GFP_ATOMIC, kern);
	psk =  (struct xaprc00x_pinfo *)sk;
	if (!sk)
	{
		printk( KERN_ERR "scm_proxy: ENOMEM when creating socket\n" );
		return -ENOMEM;
	}

	ret = scm_proxy_open_socket(&psk->local_id);

	return ret;
}

/**
 * Proto family definition
 */
static const struct net_proto_family xaprc00x_family_ops = 
{
	.family		= PF_PSOCK,
	.owner		= THIS_MODULE,
	.create		= scm_sock_create
};

/**
 * psock socket initialization, will register the protocol and socket types with the kernel
 * So the kernel can create sockets of this type when asked for
 */
static int __init xaprc00x_init_sockets(void)
{
	int err;
	err = proto_register(&xaprc00x_proto, 0);
	if ( err < 0 )
	{
		printk( KERN_INFO "Error registering psock protocol\n" );
		return err;
	}

	err = sock_register( &xaprc00x_family_ops );
	if ( err < 0 )
	{
		printk( KERN_INFO "Error registering socket\n" );
		return err;
	}

	return err;
}

/**
 * Cleanup and unregister registred types 
 */
static void __exit xaprc00x_cleanup_sockets(void)
{
	proto_unregister( &xaprc00x_proto );
	sock_unregister( xaprc00x_family_ops.family );
}

subsys_initcall(xaprc00x_init_sockets);
module_exit(xaprc00x_cleanup_sockets);
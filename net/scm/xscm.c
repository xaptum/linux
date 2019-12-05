// SPDX-License-Identifier: GPL-2.0+
/*
 * xscm.c -- A socket driver for Xaptums SCM implementation
 *
 * Copyright (C) 2018-2019 Xaptum, Inc.
 */
#include <linux/module.h>
#include <linux/net.h>
#include <net/sock.h>
#include <linux/xscm.h>

#define XAPRC00X_SK_BUFF_SIZE 512
#define XAPRC00X_SK_SND_TIMEO 1000

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Daniel Berliner");
MODULE_DESCRIPTION("SCM Socket Driver");
MODULE_VERSION("0.0.1");

/* SCM Proxy external defs */
extern void scm_proxy_close_socket(int local_id, void *context);
extern int scm_proxy_open_socket(int *local_id, void *context);
extern int scm_proxy_connect_socket(int local_id, struct sockaddr *addr,
	int alen, void *context);
extern void scm_proxy_wait_ack(struct scm_packet **packet, int msg_id);

/**
 * In addition to the Linux sock information we need to keep track of the local
 * ID given to us by the proxy
 */
struct xaprc00x_pinfo {
	struct sock		sk;
	int			local_id;
};


/* This socket driver may only be linked to one SCM proxy instance */
static void *g_proxy_context;

/**
 * Function called for socket shutdown
 */
static int xaprc00x_sock_shutdown(struct socket *sock, int how)
{
	struct sock *sk = sock->sk;
	struct xaprc00x_pinfo *psk = (struct xaprc00x_pinfo *)sk;

	if (!sk)
		return 0;

	if (!sk->sk_shutdown)
		sk->sk_shutdown = SHUTDOWN_MASK;

	scm_proxy_close_socket(psk->local_id, g_proxy_context);

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

	if (!sk)
		return 0;

	err = xaprc00x_sock_shutdown(sock, 2);

	sock_orphan(sk);

	sock_set_flag(sk, SOCK_DEAD);
	sock_put(sk);

	return err;
}

/**
 * Function for connecting a socket
 */
static int xaprc00x_sock_connect(struct socket *sock, struct sockaddr *addr,
	int alen, int flags)
{
	int ret;
	struct xaprc00x_pinfo *psk = (struct xaprc00x_pinfo *)sock->sk;

	ret = scm_proxy_connect_socket(psk->local_id, addr, alen,
		g_proxy_context);
	return ret;
}

/**
 * Function for sending a msg over the socket
 */
static int xaprc00x_sock_sendmsg(struct socket *sock,
				 struct msghdr *msg, size_t len)
{
	int res, r;
	void *data = kmalloc(len, GFP_KERNEL);
	struct xaprc00x_pinfo *psk = (struct xaprc00x_pinfo *)sock->sk;

	return 0;
}

/**
 * Function for recv msg from the socket
 */
static int xaprc00x_sock_recvmsg(struct socket *sock,
				struct msghdr *msg, size_t size, int flags)
{
	struct xaprc00x_pinfo *psk = (struct xaprc00x_pinfo *)sock->sk;
	char *buf = kmalloc(size, GFP_KERNEL);

	kfree(buf);

	return 0;
}


/**
 * Bind an address to the socket
 */
static int xaprc00x_sock_bind(struct socket *sock, struct sockaddr *addr,
	int addr_len)
{
	return 0;
}

/**
 * Operation definitions for the psock type
 */
static const struct proto_ops xaprc00x_ops = {
	.family		= PF_PSOCK,
	.owner		= THIS_MODULE,
	.release	= xaprc00x_sock_release,
	.bind		= xaprc00x_sock_bind,
	.connect	= xaprc00x_sock_connect,
	.listen		= NULL,
	.accept		= NULL,
	.getname	= NULL,
	.sendmsg	= xaprc00x_sock_sendmsg,
	.recvmsg	= xaprc00x_sock_recvmsg,
	.shutdown	= xaprc00x_sock_shutdown,
	.setsockopt	= NULL,
	.getsockopt	= NULL,
	.ioctl		= NULL,
	.poll		= NULL,
	.socketpair	= sock_no_socketpair,
	.mmap		= sock_no_mmap
};

/**
 * PSOCK proto definition
 */
static struct proto xaprc00x_proto = {
	.name = "SCM",
	.owner = THIS_MODULE,
	.obj_size = sizeof(struct xaprc00x_pinfo)
};

/**
 * Socket destruction
 */
static void xaprc00x_sock_destruct(struct sock *sk)
{
	skb_queue_purge(&sk->sk_receive_queue);
	skb_queue_purge(&sk->sk_write_queue);
}

/**
 * Allocate socket data
 */
static struct sock *scm_sock_alloc(struct net *net, struct socket *sock,
	int proto, gfp_t prio, int kern)
{
	struct sock *sk;

	sk = sk_alloc(net, PF_PSOCK, prio, &xaprc00x_proto, kern);
	if (!sk)
		goto exit;

	sock_init_data(sock, sk);

	sk->sk_destruct = xaprc00x_sock_destruct;
	sk->sk_sndtimeo = XAPRC00X_SK_SND_TIMEO;
	sk->sk_sndbuf = XAPRC00X_SK_BUFF_SIZE;
	sk->sk_rcvbuf = XAPRC00X_SK_BUFF_SIZE;

	sock_reset_flag(sk, SOCK_ZAPPED);

	sk->sk_protocol = proto;
exit:
	return sk;
}

/**
 * Create a socket for the psock type
 */
static int scm_sock_create(struct net *net, struct socket *sock, int protocol,
	int kern)
{
	struct sock *sk;
	struct xaprc00x_pinfo *psk;
	int ret;

	sock->state = SS_UNCONNECTED;
	sock->ops = &xaprc00x_ops;

	sk = scm_sock_alloc(net, sock, protocol, GFP_ATOMIC, kern);
	if (!sk) {
		pr_err("scm_proxy: ENOMEM when creating socket\n");
		ret = -ENOMEM;
		goto exit;
	}

	psk =  (struct xaprc00x_pinfo *) sk;

	ret = scm_proxy_open_socket(&psk->local_id, g_proxy_context);

exit:
	return ret;
}

/**
 * Proto family definition
 */
static const struct net_proto_family xaprc00x_family_ops = {
	.family		= PF_PSOCK,
	.owner		= THIS_MODULE,
	.create		= scm_sock_create
};

/**
 * xaprc00x_register - Initializes the socket type and registers the calling
 * proxy instance.
 *
 * @proxy_context A pointer to the SCM proxy instance
 *
 * Initializes SCM socket protocol and remembers a pointer to the proxys
 * inst to send back whenver our driver calls the proxy.
 *
 * Returns: A pointer to the instance for this proxy.
 *
 * @notes
 * When the SCM socket is initialized it must have an instance of the proxy to
 * pass back when it makes calls. This driver can only use one instance of the
 * SCM proxy but the SCM proxy may have many instances.
 *
 * This function will be called by the SCM proxy when it is ready to transmit
 * data between this module and the USB device.
 */
int xaprc00x_register(void *proxy_context)
{
	int err;

	g_proxy_context = proxy_context;

	err = proto_register(&xaprc00x_proto, 0);
	if (err < 0) {
		pr_debug("Error registering psock protocol");
		goto error;
	}

	err = sock_register(&xaprc00x_family_ops);
	if (err < 0) {
		pr_debug("Error registering socket");
		goto error;
	}

	return 0;
error:
	g_proxy_context = NULL;
	return err;
}
EXPORT_SYMBOL_GPL(xaprc00x_register);

/**
 * Cleanup and unregister registred types
 */
static void __exit xaprc00x_cleanup_sockets(void)
{
	proto_unregister(&xaprc00x_proto);
	sock_unregister(xaprc00x_family_ops.family);
	g_proxy_context = NULL;
}

static int __init xaprc00x_init_sockets(void)
{
	return 0;
}

subsys_initcall(xaprc00x_init_sockets);
module_exit(xaprc00x_cleanup_sockets);

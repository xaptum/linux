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
#include "xscm_extern.h"
#include <linux/rhashtable.h>

#define XAPRC00X_SK_BUFF_SIZE 512
#define XAPRC00X_SK_SND_TIMEO 1000

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Daniel Berliner");
MODULE_DESCRIPTION("SCM Socket Driver");
MODULE_VERSION("0.0.1");

/**
 * In addition to the Linux sock information we need to keep track of the local
 * ID given to us by the proxy
 */
enum xaprc00x_state {
	SCM_UNOPEN=0, /* Initial state, unopened */
	SCM_ESTABLISHED, /* Connection established */
	SCM_SYN_SENT, /* Sent a connection request, waiting for ACK */
	SCM_CLOSING, /* Our side has closed, waiting for host */
	SCM_CLOSE_WAIT, /* Remote has shut down and is waiting for us */
	SCM_CLOSE, /* Close has been completed */

	SCM_STATE_MAX
};
struct xaprc00x_pinfo {
	struct sock		sk;
	int			local_id;
	atomic_t		state; /* enum xaprc00x_state */
	struct semaphore wait_sem;
	struct scm_packet *wait_ack;
	struct rhash_head hash;
};

static struct rhashtable_params ht_parms = {
	.nelem_hint = 8,
	.key_len = sizeof(int),
	.key_offset = offsetof(struct xaprc00x_pinfo, local_id),
	.head_offset = offsetof(struct xaprc00x_pinfo, hash),
};

struct sock *xaprc00x_get_sock(int key);

/* This socket driver may only be linked to one SCM proxy instance */
static void *g_proxy_context;
struct rhashtable g_scm_socket_table;
static atomic_t g_sock_id;

/**
 * Handles internal socket closing procedures by removing the sock from the
 * internal lookup table and closing the socket on the Linux side.
 */
static void xaprc00x_sock_shutdown_internal(struct sock *sk)
{
	struct xaprc00x_pinfo *psk = (struct xaprc00x_pinfo *)sk;

	if (!sk->sk_shutdown)
		sk->sk_shutdown = SHUTDOWN_MASK;

	rhashtable_remove_fast(&g_scm_socket_table, &psk->hash, ht_parms);

	release_sock(sk);
}

/**
 * Function called for socket shutdown
 */
static int xaprc00x_sock_shutdown(struct socket *socket, int how)
{
	struct sock *sk = socket->sk;
	struct xaprc00x_pinfo *psk = (struct xaprc00x_pinfo *)sk;
	int local_id;

	if (!sk)
		return 0;

	local_id = psk->local_id;

	xaprc00x_sock_shutdown_internal(sk);

	scm_proxy_close_socket(local_id, g_proxy_context);

	return 0;
}

/**
 * For the proxy to call when the host initiated a close
 * This function will not send anything to the host becuase the sock is already
 * closed and the caller of this function is responsible for sending the ACK.
 */
int xaprc00x_sock_handle_shutdown(int sock_id)
{
	struct sock *sk;
	struct xaprc00x_pinfo *psk;

	sk = xaprc00x_get_sock(sock_id);
	psk = (struct xaprc00x_pinfo *) sk;

	xaprc00x_sock_shutdown_internal(sk);
}
EXPORT_SYMBOL_GPL(xaprc00x_sock_handle_shutdown);

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
static void xaprc00x_def_write_space(struct sock *sk)
{
	struct socket_wq *wq;
	struct xaprc00x_pinfo *psk = (struct xaprc00x_pinfo *)sk;

	wq = rcu_dereference(sk->sk_wq);
	wake_up_interruptible_all(&wq->wait);
	sk_wake_async(sk, SOCK_WAKE_SPACE, POLL_OUT);
}

static void xaprc00x_def_readable(struct sock *sk)
{
	struct socket_wq *wq;
	struct xaprc00x_pinfo *psk = (struct xaprc00x_pinfo *)sk;

	wq = rcu_dereference(sk->sk_wq);
	wake_up_interruptible_sync_poll(&wq->wait, POLLIN | POLLPRI |
		POLLRDNORM | POLLRDBAND);
	sk_wake_async(sk, SOCK_WAKE_WAITD, POLL_IN);
}

/**
 * Funciton for handling a CONNECT ack
 */
void xaprc00x_sock_connect_ack(int sock_id, struct scm_packet *packet)
{
	int new_status;
	struct socket_wq *wq;
	struct xaprc00x_pinfo *psk;
	struct sock *sk;
	int status;

	status = packet->ack.code;
	psk = (struct xaprc00x_pinfo *) xaprc00x_get_sock(sock_id);

	/* This usually means the sock was shut down while in transit. */
	if (!psk) {
		pr_err("%s: Socket %d not found",
			__func__, sock_id);
		return;
	}

	sk = &psk->sk;

	if (status == SCM_E_SUCCESS) {
		new_status = SCM_ESTABLISHED;

		/* Let poll know that we can write now */
		sk->sk_write_space = xaprc00x_def_write_space;
		sk->sk_data_ready = xaprc00x_def_readable;
		sk->sk_write_space(&psk->sk);
	} else {
		new_status = SCM_CLOSE;

		wq = rcu_dereference(sk->sk_wq);
		wake_up_interruptible_all(&wq->wait);
		sk_wake_async(sk, SOCK_WAKE_SPACE, POLL_OUT);
	}

	atomic_set(&psk->state, new_status);

	/* Unblock the calling thread if it is waiting */
	/* Either pass the reponse packet to the waiting call or free it now */
	if(down_trylock(&psk->wait_sem)) {
		psk->wait_ack = packet;
	} else {
		kfree(packet);
	}
	up(&psk->wait_sem);

}
EXPORT_SYMBOL_GPL(xaprc00x_sock_connect_ack);

/**
 * Funciton for sending a CONNECT
 */
static int xaprc00x_sock_connect(struct socket *sock, struct sockaddr *addr,
	int alen, int flags)
{
	int ret;
	struct xaprc00x_pinfo *psk;
	int state;

	psk = (struct xaprc00x_pinfo *)sock->sk;
	state = atomic_read(&psk->state);

	if (state == SCM_SYN_SENT)
		ret = -EALREADY;
	else if (state == SCM_ESTABLISHED)
		ret = -EISCONN;
	else {
		scm_proxy_connect_socket(psk->local_id, addr, alen,
			g_proxy_context);
		atomic_set(&psk->state, SCM_SYN_SENT);

		/* Block for ACK if nonblock isn't set */
		if (!(flags & SOCK_NONBLOCK)) {
			down(&psk->wait_sem);

			ret = psk->wait_ack->ack.code;

			/* The proxy expects us to free the buffer */
			kfree(psk->wait_ack);
			psk->wait_ack = NULL;
		}
	}

	return ret;
}

/**
 * Function for sending a msg over the socket
 */
static int xaprc00x_sock_sendmsg(struct socket *sock,
				 struct msghdr *msg, size_t len)
{
	return -EAGAIN;
}

/**
 * Function for recv msg from the socket
 */
static int xaprc00x_sock_recvmsg(struct socket *sock,
				struct msghdr *msg, size_t size, int flags)
{
	return -EAGAIN;
}

static unsigned int xaprc00x_sock_poll(struct file *file, struct socket *sock,
	poll_table *wait)
{
	struct xaprc00x_pinfo *psk;
	unsigned int mask;

	psk = (struct xaprc00x_pinfo *)sock->sk;
	mask = 0;

	sock_poll_wait(file, sk_sleep(sock->sk), wait);

	/* Connected sockets are always writable */
	if (atomic_read(&psk->state) == SCM_ESTABLISHED)
		mask |= POLLOUT | POLLWRNORM | POLLWRBAND;

	return mask;
}
/**
 * Operation definitions for the psock type
 */
static const struct proto_ops xaprc00x_ops = {
	.family		= PF_PSOCK,
	.owner		= THIS_MODULE,
	.release	= xaprc00x_sock_release,
	.bind		= sock_no_bind,
	.connect	= xaprc00x_sock_connect,
	.listen		= sock_no_listen,
	.accept		= sock_no_accept,
	.getname	= sock_no_getname,
	.sendmsg	= xaprc00x_sock_sendmsg,
	.recvmsg	= xaprc00x_sock_recvmsg,
	.shutdown	= xaprc00x_sock_shutdown,
	.setsockopt	= sock_no_setsockopt,
	.getsockopt	= sock_no_getsockopt,
	.ioctl		= sock_no_ioctl,
	.poll		= xaprc00x_sock_poll,
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
	int tmp_id;

	sock->state = SS_UNCONNECTED;
	sock->ops = &xaprc00x_ops;

	sk = scm_sock_alloc(net, sock, protocol, GFP_ATOMIC, kern);
	if (!sk) {
		pr_err("scm_proxy: ENOMEM when creating socket\n");
		ret = -ENOMEM;
		goto exit;
	}

	psk =  (struct xaprc00x_pinfo *) sk;
	atomic_set(&psk->state, SCM_UNOPEN);

	sema_init(&psk->wait_sem, 0);

	/* Create the socks entry in our table */
	psk->local_id = atomic_inc_return(&g_sock_id);
	rhashtable_lookup_insert_fast(&g_scm_socket_table,
		&psk->hash, ht_parms);

	/* Send the OPEN command to the proxy */
	scm_proxy_open_socket(psk->local_id, g_proxy_context);

	/* Block until we get an ACK */
	down(&psk->wait_sem);

	/* Handle the ack and reinsert on success */
	ret = psk->wait_ack->ack.code;
	if (ret) {
		pr_err("scm_proxy: Host failed OPEN with code %d", ret);
		rhashtable_remove_fast(&g_scm_socket_table, &psk->hash,
			ht_parms);
	}

	/* The proxy expects us to free the buffer */
	kfree(psk->wait_ack);
	psk->wait_ack = NULL;

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

void xaprc00x_sock_open_ack(int sock_id, struct scm_packet *ack)
{
	struct xaprc00x_pinfo *pending_sock;

	pending_sock = (struct xaprc00x_pinfo *)
		xaprc00x_get_sock(sock_id);

	/* These should never happen */
	if (!pending_sock) {
		pr_err("%s: Sock %d not found\n",
			__func__, sock_id);
		return;
	}
	if (pending_sock->wait_ack) {
		pr_err("%s: Sock %d busy\n",
			__func__, sock_id);
		return;
	}

	pending_sock->wait_ack = ack;
	up(&pending_sock->wait_sem);
}
EXPORT_SYMBOL_GPL(xaprc00x_sock_open_ack);

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

	if (g_proxy_context) {
		err = -EEXIST;
		goto exit;
	}
	g_proxy_context = proxy_context;

	err = proto_register(&xaprc00x_proto, 0);
	if (err < 0) {
		pr_debug("Error registering psock protocol");
		goto clear_context;
	}

	err = sock_register(&xaprc00x_family_ops);
	if (err < 0) {
		pr_debug("Error registering socket");
		goto clear_context;
	}

	return 0;
clear_context:
	g_proxy_context = NULL;
exit:
	return err;
}
EXPORT_SYMBOL_GPL(xaprc00x_register);

struct sock *xaprc00x_get_sock(int key)
{
	return rhashtable_lookup_fast(&g_scm_socket_table, &key, ht_parms);
}
EXPORT_SYMBOL_GPL(xaprc00x_get_sock);

/**
 * Cleanup and unregister registred types
 */
static void __exit xaprc00x_cleanup_sockets(void)
{
	proto_unregister(&xaprc00x_proto);
	sock_unregister(xaprc00x_family_ops.family);
	rhashtable_destroy(&g_scm_socket_table);
}

static int __init xaprc00x_init_sockets(void)
{
	rhashtable_init(&g_scm_socket_table, &ht_parms);
	return 0;
}

subsys_initcall(xaprc00x_init_sockets);
module_exit(xaprc00x_cleanup_sockets);

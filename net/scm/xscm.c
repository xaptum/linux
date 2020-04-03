// SPDX-License-Identifier: GPL-2.0+
/**
 * xscm.c -- A socket driver for Xaptums SCM implementation
 *
 * Copyright (C) 2018-2019 Xaptum, Inc.
 */
#include <linux/module.h>
#include <linux/net.h>
#include <linux/xscm.h>
#include <linux/rhashtable.h>
#include <linux/sched/signal.h>
#include <net/sock.h>

#include "xscm_extern.h"
#define XAPRC00X_SK_BUFF_SIZE 512
#define XAPRC00X_SK_SND_TIMEO (HZ * 30)

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Daniel Berliner");
MODULE_DESCRIPTION("SCM Socket Driver");
MODULE_VERSION("0.0.1");

/**
 * In addition to the Linux sock information we need to keep track of the local
 * ID given to us by the proxy
 */
enum xaprc00x_state {
	SCM_UNOPEN = 0, /* Initial state, unopened */
	SCM_ESTABLISHED, /* Connection established */
	SCM_SYN_SENT, /* Sent a connection request, waiting for ACK */
	/* A connection request has been responded to but not processed */
	SCM_SYN_RECV,
	SCM_CLOSING, /* Our side has closed, waiting for host */
	SCM_CLOSE_WAIT, /* Remote has shut down and is waiting for us */
	SCM_CLOSE, /* Close has been completed or open is in flight */

	SCM_STATE_MAX
};

struct xaprc00x_pinfo {
	struct sock		sk;
	int			local_id;
	atomic_t		state; /* enum xaprc00x_state */
	__u8			so_error;
	char			*read_cache;
	size_t			read_cache_offset;
	size_t			read_cache_bytes_used;
	size_t			read_cache_size;
	struct scm_packet *wait_ack;
	struct rhash_head hash;
};

static struct rhashtable_params ht_parms = {
	.nelem_hint = 8,
	.key_len = sizeof(int),
	.key_offset = offsetof(struct xaprc00x_pinfo, local_id),
	.head_offset = offsetof(struct xaprc00x_pinfo, hash),
};

/* Forward Declarations */
struct sock *xaprc00x_get_sock(int key);

/* This socket driver may only be linked to one SCM proxy instance */
static void *g_proxy_context;
struct rhashtable g_scm_socket_table;
static atomic_t g_sock_id;

/**
 * Closes the socket on the device side.
 */
static void xaprc00x_sock_side_shutdown_internal(struct sock *sk, int how)
{
	struct xaprc00x_pinfo *psk = (struct xaprc00x_pinfo *)sk;

	lock_sock(sk);
	sk->sk_shutdown |= how;

	/**
	 * Note: This is mostly legacy since sendmsg and recvmsg only use
	 * sk_shutdown flags. Removal of psk->state is likely in future
	 * releases.
	 */
	atomic_set(&psk->state, SCM_CLOSE);
	sk->sk_state_change(sk);
	release_sock(sk);
}

/**
 * When the device initiates a shutdown it performs the internal tasks and
 * sends a command to the host.
 */
static int xaprc00x_sock_side_shutdown(struct socket *socket, int how)
{
	struct sock *sk = socket->sk;
	struct xaprc00x_pinfo *psk = (struct xaprc00x_pinfo *)sk;
	int local_id;

	/**
	 * maps 0->1 has the advantage of making bit 1 rcvs and
	 * 1->2 bit 2 snds.
	 * 2->3
	 */
	how++;
	if ((how & ~SHUTDOWN_MASK) || !how) /* MAXINT->0 */
		return -EINVAL;

	xaprc00x_sock_side_shutdown_internal(sk, how);

	/* Send shutdown to peer */
	scm_proxy_close_socket(psk->local_id, g_proxy_context);
	return 0;
}

/**
 * For the proxy to run when a shutdown is received from the host.
 */
int xaprc00x_sock_handle_host_side_shutdown(int sock_id, int how)
{
	struct sock *sk;

	/**
	 * maps 0->1 has the advantage of making bit 1 rcvs and
	 * 1->2 bit 2 snds.
	 * 2->3
	 */
	how++;
	if ((how & ~SHUTDOWN_MASK) || !how) /* MAXINT->0 */
		return -EINVAL;

	sk = xaprc00x_get_sock(sock_id);
	if (sk)
		xaprc00x_sock_side_shutdown_internal(sk, how);

	return 0;
}
EXPORT_SYMBOL_GPL(xaprc00x_sock_handle_host_side_shutdown);

static int xaprc00x_sock_side_release(struct socket *sock)
{
	struct sock *sk = sock->sk;

	if (sk) {
		struct xaprc00x_pinfo *psk = (struct xaprc00x_pinfo *)sk;

		lock_sock(sk);

		rhashtable_remove_fast(&g_scm_socket_table, &psk->hash,
				       ht_parms);
		sock->sk = NULL;
		sk->sk_shutdown = SHUTDOWN_MASK;
		sk->sk_state_change(sk);
		sock_orphan(sk);

		release_sock(sk);

		sock_put(sk);
	} else {
		pr_err("%s: Given sock->sk==NULL. Hash table corruption "
			"possible.", __func__);
	}

	return 0;
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
	struct socket_wq *wq;
	struct xaprc00x_pinfo *psk;
	struct sock *sk;

	sk = xaprc00x_get_sock(sock_id);
	psk = (struct xaprc00x_pinfo *)sk;

	/* This usually means the sock was shut down while in transit. */
	if (!psk) {
		pr_err("%s: Socket %d not found",
			__func__, sock_id);
		return;
	}
	
	wq = rcu_dereference(sk->sk_wq);

	/* Let the sock know we got a response */
	psk->wait_ack = packet;
	atomic_set(&psk->state, SCM_SYN_RECV);
	wake_up_interruptible_all(&wq->wait);
}
EXPORT_SYMBOL_GPL(xaprc00x_sock_connect_ack);

static long xaprc00x_wait_for_connect(struct sock *sk, long timeo)
{
	struct xaprc00x_pinfo *psk;

	psk = (struct xaprc00x_pinfo *)sk;

	DEFINE_WAIT_FUNC(wait, woken_wake_function);
	add_wait_queue(sk_sleep(sk), &wait);

	while (atomic_read(&psk->state) == SCM_SYN_SENT) {
		release_sock(sk);
		timeo = wait_woken(&wait, TASK_INTERRUPTIBLE, timeo);
		lock_sock(sk);

		if (signal_pending(current) || !timeo)
			break;
	}

	remove_wait_queue(sk_sleep(sk), &wait);
	return timeo;
}

/**
 * xaprc00x_realloc_shift - Reallocs a buffer but only copies part of the data
 *
 * @p A pointer to the location of the memory to be reallocated
 * @new_size The minimum size for the new buffer
 * @flags Flags to pass to kmalloc
 * @copy_start The offset to apply when copying the old data
 * @copy_len The number of bytes to copy to the new buffer
 *
 * This function uses kmalloc and free to act like krealloc, except instead of
 * copying the entire buffer over to the new memory, only a single continuous
 * segment of data is taken. This data can start anywhere in the buffer and can
 * be any length.
 *
 * Returns: The new length of the buffer
 *
 * @notes
 * This function may generate a segment violation if copy_start+copy_len
 * exceeds the length of the original buffer.
 *
 * This function will cause undefined behavior if *p is not a block of memory
 * defined by the kmalloc family of functions.
 *
 * This function will round new_size up to the nearest power of 2 when
 * selecting a new buffer size.
 */
static size_t xaprc00x_realloc_shift(void **p, size_t new_size, gfp_t flags,
	size_t copy_start, size_t copy_len)
{
	char *new_mem = kmalloc(new_size, flags);

	new_size = round_up(new_size, 2);

	if (p) {
		memcpy(new_mem, ((char *)*p) + copy_start, copy_len);
		kfree(*p);
	}

	*p = new_mem;
	return new_size;
}

void xaprc00x_sock_transmit(int sock_id, void *data, int len)
{
	struct xaprc00x_pinfo *psk;
	struct sock *sk;
	int free_space;
	int noshift_len;
	int write_offset;

	psk = (struct xaprc00x_pinfo *)xaprc00x_get_sock(sock_id);

	/* This usually means the sock was shut down while in transit. */
	if (!psk) {
		pr_err("%s: Socket %d not found\n", __func__, sock_id);
		return;
	}

	sk = &psk->sk;

	lock_sock(sk);

	/* How much space is currently in the buffer? */
	free_space = psk->read_cache_size - psk->read_cache_bytes_used;

	/* The length required to append the incoming data without shifting */
	noshift_len =
		psk->read_cache_offset + psk->read_cache_bytes_used + len;

	/* If there is not enough space in the buffer, reallocate */
	if (free_space < len) {
		psk->read_cache_size =
			xaprc00x_realloc_shift(
				(void **)&psk->read_cache,
				psk->read_cache_size + len,
				GFP_KERNEL,
				psk->read_cache_offset,
				psk->read_cache_bytes_used);
		psk->read_cache_offset = 0;
	} else if (noshift_len > psk->read_cache_size) {
		/**
		 * If there is sufficient room but it isn't continuous then
		 * move existing to the top.
		 */
		memcpy(psk->read_cache,
			psk->read_cache + psk->read_cache_offset,
			psk->read_cache_bytes_used);
		psk->read_cache_offset = 0;
	}

	/* Append the incoming data immediately after the existing data */
	write_offset = psk->read_cache_offset + psk->read_cache_bytes_used;
	memcpy(psk->read_cache + write_offset, data, len);
	psk->read_cache_bytes_used += len;

	release_sock(sk);
	sk->sk_data_ready(sk);
}
EXPORT_SYMBOL_GPL(xaprc00x_sock_transmit);

/**
 * Funciton for sending a CONNECT
 */
static int xaprc00x_sock_connect(struct socket *sock, struct sockaddr *addr,
	int alen, int flags)
{
	struct xaprc00x_pinfo *psk;
	struct sock *sk;
	int state;
	int ret = -1;

	sk = sock->sk;
	psk = (struct xaprc00x_pinfo *)sk;

	lock_sock(sk);

	state = atomic_read(&psk->state);

	if (state == SCM_SYN_SENT) {
		ret = -EALREADY;
	} else if (state == SCM_ESTABLISHED) {
		ret = -EISCONN;
	} else {
		int new_status;
		long timeo = sock_sndtimeo(sk, flags & O_NONBLOCK);

		atomic_set(&psk->state, SCM_SYN_SENT);
		scm_proxy_connect_socket(psk->local_id, addr, alen,
			g_proxy_context);

		/* Exit immediately if asked not to block */
		if (!timeo || !xaprc00x_wait_for_connect(sk, timeo)) {
			ret = -EINPROGRESS;
			goto out;
		}

		/* If interrupted the error is either -ERESTARTSYS or -EINTR */
		ret = sock_intr_errno(timeo);
		if (signal_pending(current))
			goto out;

		if (psk->wait_ack->ack.code == SCM_E_SUCCESS) {
			new_status = SCM_ESTABLISHED;

			/* Let poll know that we can write now */
			sk->sk_write_space = xaprc00x_def_write_space;
			sk->sk_data_ready = xaprc00x_def_readable;
			sk->sk_write_space(&psk->sk);
			ret = 0;
		} else {
			struct socket_wq *wq = rcu_dereference(sk->sk_wq);

			new_status = SCM_CLOSE;

			wake_up_interruptible_all(&wq->wait);
			sk_wake_async(sk, SOCK_WAKE_SPACE, POLL_OUT);
			ret = -1;
		}
		atomic_set(&psk->state, new_status);
	}

out:
	release_sock(sk);
	return ret;
}

/**
 * Function for sending a msg over the socket
 */
static int xaprc00x_sock_sendmsg(struct socket *sock,
				 struct msghdr *msg, size_t len)
{
	void *data;
	int bytes_copied;
	int bytes_sent;
	struct xaprc00x_pinfo *psk;
	struct sock *sk;

	sk = sock->sk;
	psk = (struct xaprc00x_pinfo *)sk;

	/* If the sock has already been freed */
	if (!sk) {
		bytes_sent = -EPIPE;
		goto out_nolock;
	}

	lock_sock(sk);

	/* If outgoing transmissions have been shut down */
	if (sk->sk_shutdown & SEND_SHUTDOWN) {
		bytes_sent = -EPIPE;
		goto out_release;
	}

	/* If not connected */
	if (atomic_read(&psk->state) != SCM_ESTABLISHED) {
		bytes_sent = -ENOTCONN;
		goto out_release;
	}

	/* Copy the data over */
	data = kmalloc(len, GFP_KERNEL);
	bytes_copied = copy_from_iter(data, len, &msg->msg_iter);

	/* This operation can be lengthy and we don't need the lock */
	release_sock(sk);
	bytes_sent = scm_proxy_write_socket(psk->local_id, data,
		bytes_copied, g_proxy_context);
	goto out_nolock;

out_release:
	release_sock(sk);
out_nolock:
	return bytes_sent;
}

static int xaprc00x_sock_wait_for_data(struct socket *sock,
	int min_bytes, int timeo)
{
	struct xaprc00x_pinfo *psk;
	struct sock *sk;

	sk = sock->sk;
	psk = (struct xaprc00x_pinfo *)sk;

	DEFINE_WAIT_FUNC(wait, woken_wake_function);
	add_wait_queue(sk_sleep(sk), &wait);

	while (psk->read_cache_bytes_used < min_bytes) {
		release_sock(sk);
		timeo = wait_woken(&wait, TASK_INTERRUPTIBLE, timeo);
		lock_sock(sk);

		if (signal_pending(current) || !timeo)
			break;
	}

	remove_wait_queue(sk_sleep(sk), &wait);
	return timeo;
}

/**
 * Function for recv msg from the socket
 */
static int xaprc00x_sock_recvmsg(struct socket *sock,
				struct msghdr *msg, size_t size, int flags)
{
	struct xaprc00x_pinfo *psk;
	int target;
	long timeo;
	struct sock *sk;
	int ret = 0;

	sk = sock->sk;
	psk = (struct xaprc00x_pinfo *)sk;

	lock_sock(sock->sk);

	timeo = sock_sndtimeo(sk, flags & MSG_DONTWAIT);

	/* Handle not having enough bytes to return immediately */
	target = (flags & MSG_WAITALL) ? size : 1;
	if (target > psk->read_cache_bytes_used &&
		!(sk->sk_shutdown & RCV_SHUTDOWN)) {
		/* Exit if we can't block or timed out before data came in */
		if (!timeo && !xaprc00x_wait_for_connect(sk, timeo)) {
			ret = -EWOULDBLOCK;
			goto out;
		}

		xaprc00x_sock_wait_for_data(sock, target, timeo);

		/* If interrupted the error is either -ERESTARTSYS or -EINTR */
		if (signal_pending(current)) {
			ret = sock_intr_errno(timeo);
			goto out;
		}
	}

	if (psk->read_cache_bytes_used > 0) {
		/* Never return more bytes than requested */
		ret = (psk->read_cache_bytes_used > size) ?
			size : psk->read_cache_bytes_used;
		copy_to_iter(psk->read_cache + psk->read_cache_offset,
			ret, &msg->msg_iter);
		psk->read_cache_bytes_used -= ret;
		psk->read_cache_offset += ret;
	}

out:
	release_sock(sock->sk);
	return ret;
}

static unsigned int xaprc00x_sock_poll(struct file *file, struct socket *socket,
	poll_table *wait)
{
	struct xaprc00x_pinfo *psk;
	struct sock *sk;
	unsigned int mask;
	int state;

	sk = socket->sk;
	psk = (struct xaprc00x_pinfo *)sk;
	mask = 0;

	sock_poll_wait(file, socket, wait);

	state = atomic_read(&psk->state);

	/* POLLHUP if and only if both sides are shut down. */
	if (sk->sk_shutdown == SHUTDOWN_MASK && state == SCM_CLOSE) {
		mask |= POLLHUP;
		return mask;
	}
	if (sk->sk_shutdown & RCV_SHUTDOWN)
		mask |= POLLIN | POLLRDNORM | POLLRDHUP;

	/* Decide readability */
	if (psk->read_cache_bytes_used > 0)
		mask |= POLLIN | POLLRDNORM;

	/* Connected sockets are always writable */
	if (state == SCM_ESTABLISHED)
		mask |= POLLOUT | POLLWRNORM | POLLWRBAND;

	return mask;
}

/**
 * Operation definitions for the psock type
 */
static const struct proto_ops xaprc00x_ops = {
	.family		= PF_SCM,
	.owner		= THIS_MODULE,
	.release	= xaprc00x_sock_side_release,
	.shutdown	= xaprc00x_sock_side_shutdown,
	.bind		= sock_no_bind,
	.connect	= xaprc00x_sock_connect,
	.listen		= sock_no_listen,
	.accept		= sock_no_accept,
	.getname	= sock_no_getname,
	.sendmsg	= xaprc00x_sock_sendmsg,
	.recvmsg	= xaprc00x_sock_recvmsg,
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
 * Allocate socket data
 */
static struct sock *scm_sock_alloc(struct net *net, struct socket *sock,
	int proto, gfp_t prio, int kern)
{
	struct sock *sk;

	sk = sk_alloc(net, PF_SCM, prio, &xaprc00x_proto, kern);
	if (!sk)
		goto exit;

	sock_init_data(sock, sk);

	sk->sk_destruct = NULL;
	sk->sk_sndtimeo = XAPRC00X_SK_SND_TIMEO;
	sk->sk_sndbuf = XAPRC00X_SK_BUFF_SIZE;
	sk->sk_rcvbuf = XAPRC00X_SK_BUFF_SIZE;

	refcount_set(&sk->sk_refcnt, 1);

	sock_reset_flag(sk, SOCK_ZAPPED);

	sk->sk_protocol = proto;
exit:
	return sk;
}

static long xaprc00x_wait_for_create(struct sock *sk, long timeo)
{
	struct xaprc00x_pinfo *psk;

	psk = (struct xaprc00x_pinfo *)sk;

	DEFINE_WAIT_FUNC(wait, woken_wake_function);
	add_wait_queue(sk_sleep(sk), &wait);

	while (atomic_read(&psk->state) != SCM_UNOPEN) {
		timeo = wait_woken(&wait, TASK_INTERRUPTIBLE, timeo);

		/* If we were interrupted or hit the timeout */
		if (signal_pending(current) || !timeo)
			break;
	}

	remove_wait_queue(sk_sleep(sk), &wait);
	return timeo;
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
	long timeo;

	sock->state = SS_UNCONNECTED;
	sock->ops = &xaprc00x_ops;

	sk = scm_sock_alloc(net, sock, protocol, GFP_ATOMIC, kern);
	if (!sk) {
		pr_err("scm_proxy: ENOMEM when creating socket\n");
		ret = -ENOMEM;
		goto out;
	}

	psk =  (struct xaprc00x_pinfo *)sk;
	atomic_set(&psk->state, SCM_UNOPEN);

	/* Create the socks entry in our table */
	psk->local_id = atomic_inc_return(&g_sock_id);
	rhashtable_lookup_insert_fast(&g_scm_socket_table,
		&psk->hash, ht_parms);
	atomic_set(&psk->state, SCM_CLOSE);

	/* Send the OPEN command to the proxy */
	scm_proxy_open_socket(psk->local_id, g_proxy_context);

	/* Block until we get an ACK */
	/* Blocking it assumed to be allowed for the time being */
	timeo = sk->sk_sndtimeo;

	/* Exit immediately if the block timed out */
	if (!xaprc00x_wait_for_create(sk, timeo)) {
		ret = -EINPROGRESS;
		goto out;
	}

	/* If interrupted the error is either -ERESTARTSYS or -EINTR */
	if (signal_pending(current)) {
		ret = sock_intr_errno(timeo);
		goto out;
	}

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

out:
	return ret;
}

/**
 * Proto family definition
 */
static const struct net_proto_family xaprc00x_family_ops = {
	.family		= PF_SCM,
	.owner		= THIS_MODULE,
	.create		= scm_sock_create
};

void xaprc00x_sock_open_ack(int sock_id, struct scm_packet *ack)
{
	struct xaprc00x_pinfo *psk;
	struct sock *sk;
	struct socket_wq *wq;

	sk = xaprc00x_get_sock(sock_id);
	psk = (struct xaprc00x_pinfo *)sk;
	wq = rcu_dereference(sk->sk_wq);

	/* These should never happen */
	if (!psk) {
		pr_err("%s: Sock %d not found\n",
			__func__, sock_id);
		return;
	}
	if (psk->wait_ack) {
		pr_err("%s: Sock %d busy\n",
			__func__, sock_id);
		return;
	}

	psk->wait_ack = ack;
	atomic_set(&psk->state, SCM_UNOPEN);

	wake_up_interruptible_all(&wq->wait);
}
EXPORT_SYMBOL_GPL(xaprc00x_sock_open_ack);

/**
 * xaprc00x_register - Initializes the socket type and registers the calling
 * proxy instance.
 *
 * @proxy_context A pointer to the SCM proxy instance
 *
 * Initializes SCM socket protocol and remembers a pointer to the proxys
 * inst to send back whenever our driver calls the proxy.
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

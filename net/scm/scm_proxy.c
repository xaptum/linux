#include <linux/mutex.h>
#include "scm_proxy.h"
#include "scm.h"

/* For now we will just use a rotating count 0-255 */
__u8 scm_msg_id;
DEFINE_MUTEX(scm_msg_id_mutex);

/* Stubs for now */
void scm_proxy_wait_ack(struct scm_packet **packet, int msg_id)
{
	return;
}

void scm_proxy_init()
{
	mutex_init(scm_msg_id_mutex);
	scm_msg_id = 0;
}

static int scm_proxy_get_msg_id()
{
	int id;
	mutex_lock(&scm_msg_id_mutex);
	id = scm_msg_id++;
	mutex_unlock(&scm_msg_id_mutex);
	return id;
}

static void scm_proxy_assign_ip4(struct scm_packet *packet,
	struct sockaddr *addr, int alen)
{
	struct sockaddr_in *ip4_addr = (struct sockaddr_in*) addr;

	packet->connect.ip4.ip_addr = ip4_addr->sin_addr.s_addr;
	packet->connect.port = ip4_addr->sin_port;
	packet->connect.family = SCM_FAM_IP;

	packet->connect.payload_len = sizeof(struct scm_payload_connect_ip) -
		sizeof(struct scm_payload_connect_ip_addr) +
		sizeof(struct scm_payload_connect_ip4);
}

static void scm_proxy_assign_ip6(struct scm_packet *packet,
	struct sockaddr *addr)
{
	struct sockaddr_in6 *ip6_addr = (struct sockaddr_in6*) addr;

	memcpy(packet->connect.ip6.ip_addr,
		&ip6_addr->sin6_addr, sizeof(struct in6_addr));
	packet->connect.port = ip6_addr->sin6_port;
	packet->connect.scope = ip6_addr->sin6_scope_id;
	packet->connect.flow_info = ip6_addr->sin6_flowinfo;
	packet->connect.family = SCM_FAM_IP6;

	packet->connect.payload_len = sizeof(struct scm_payload_connect_ip) -
		sizeof(struct scm_payload_connect_ip_addr) +
		sizeof(struct scm_payload_connect_ip6);
}
int scm_proxy_connect_socket(int local_id, struct sockaddr *addr, int alen)
{
	struct scm_packet *ack;
	struct scm_packet *packet = kzalloc(sizeof(struct scm_packet), GFP_KERNEL);

	packet->hdr.opcode = SCM_OP_CONNECT;
	packet->hdr.msg_id = scm_proxy_get_msg_id();

	if (addr->sa_family == AF_INET &&
		alen == sizeof(struct sockaddr_in))
		scm_proxy_assign_ip4(packet, addr);
	else if (addr->sa_family == AF_INET6 &&
		alen == sizeof(struct sockaddr_in6))
		scm_proxy_assign_ip6(packet, addr);

	xaprc00x_usb_send_msg(packet, sizeof(struct scm_packet_hdr) + packet->hdr.payload_len);
	scm_proxy_wait_ack(&ack, packet->hdr.msg_id);
	return ack->connect;
}

int scm_proxy_open_socket(int *local_id)
{
	struct scm_packet *ack;
	struct scm_packet *packet = kzalloc(sizeof(struct scm_packet), GFP_KERNEL);

	packet->hdr.opcode = SCM_OP_OPEN;
	packet->hdr.msg_id = scm_proxy_get_msg_id();
	packet->hdr.payload_len = sizeof(struct scm_payload_open);
	packet->open.addr_family = SCM_FAM_IP;
	packet->open.protocol = SCM_PROTO_TCP;
	packet->open.type = SCM_TYPE_STREAM;

	xaprc00x_usb_send_msg(packet, sizeof(struct scm_packet_hdr) + packet->hdr.payload_len);

	scm_proxy_wait_ack(&ack, packet->hdr.msg_id);

	if (ack->open == 0)
		*local_id = ack->hdr.sock_id;

	return ack->open;
}

void scm_proxy_close_socket(int local_id)
{
	struct scm_packet *ack;
	struct scm_packet *packet = kzalloc(sizeof(struct scm_packet), GFP_KERNEL);

	packet->hdr.opcode = SCM_OP_CLOSE;
	packet->hdr.msg_id = scm_proxy_get_msg_id();
	packet->hdr.payload_len = 0;

	xaprc00x_usb_send_msg(packet, sizeof(struct scm_packet_hdr));

	scm_proxy_wait_ack(&ack, packet->hdr.msg_id);

	return;
}
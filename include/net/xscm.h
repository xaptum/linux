#include <linux/xscm.h>

struct scm_usb_descriptor {
	void (*scm_cmd)(char*, size_t, void*);
	void (*scm_transfer)(struct scm_packet_hdr *hdr, char*, size_t, void*);
	void (*scm_shutdown)(void*);
};


int xaprc00x_sock_handle_host_side_shutdown(int sock_id, int how);
void xaprc00x_sock_connect_ack(int sock_id, struct scm_packet *packet);
void xaprc00x_sock_transmit(int sock_id, void *data, int len);
void xaprc00x_sock_open_ack(int sock_id, struct scm_packet *ack);
int xaprc00x_register(void *proxy_context);
void *scm_proxy_init(void *usb_context, struct scm_usb_descriptor *intf);

void scm_proxy_rcv_data(struct scm_packet *packet, size_t len, void *proxy_ctx);
void scm_proxy_rcv_cmd(struct scm_packet *packet, size_t len, void *proxy_ctx);
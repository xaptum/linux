#include <linux/hss.h>

struct hss_usb_descriptor {
	void (*hss_cmd)(char*, size_t, void*);
	void (*hss_transfer)(struct hss_packet_hdr *hdr, char*, size_t, void*);
	void (*hss_shutdown)(void*);
};


int hss_sock_handle_host_side_shutdown(int sock_id, int how);
void hss_sock_connect_ack(int sock_id, struct hss_packet *packet);
void hss_sock_transmit(int sock_id, void *data, int len);
void hss_sock_open_ack(int sock_id, struct hss_packet *ack);
int hss_register(void *proxy_context);
void *hss_proxy_init(void *usb_context, struct hss_usb_descriptor *intf);

void hss_proxy_rcv_data(struct hss_packet *packet, size_t len, void *proxy_ctx);
void hss_proxy_rcv_cmd(struct hss_packet *packet, size_t len, void *proxy_ctx);

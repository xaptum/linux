//Exported net functions
int xaprc00x_sock_handle_host_side_shutdown(int sock_id, int how);
void xaprc00x_sock_connect_ack(int sock_id, struct scm_packet *packet);
void xaprc00x_sock_transmit(int sock_id, void *data, int len);
void xaprc00x_sock_open_ack(int sock_id, struct scm_packet *ack);
int xaprc00x_register(void *proxy_context);

// Exported Proxy functions
int scm_proxy_connect_socket(int local_id, struct sockaddr *addr, int alen, void *context);
int scm_proxy_open_socket(int local_id, void *context);
void scm_proxy_close_socket(int local_id, void *context);
int scm_proxy_write_socket(int sock_id, void *msg, int len, void *context);

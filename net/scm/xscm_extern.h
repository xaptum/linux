/* SCM Proxy external defs */
extern void scm_proxy_close_socket(int local_id, void *context);
extern int scm_proxy_open_socket(int local_id, void *context);
extern int scm_proxy_connect_socket(int local_id, struct sockaddr *addr,
	int alen, void *context);
extern void scm_proxy_wait_ack(struct scm_packet **packet, int msg_id);
extern int scm_proxy_write_socket(int sock_id, void *msg, int len, void *context);

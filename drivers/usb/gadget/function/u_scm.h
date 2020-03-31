/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * u_scm.h -- USB Socket Control Module (SCM) function driver
 *
 * Copyright (C) 2018-2019 Xaptum, Inc.
 */
#ifndef _U_SCM_H_
#define _U_SCM_H_

struct f_scm_opts {
	struct usb_function_instance func_inst;
	struct mutex lock;
	int refcnt;
};

/* SCM Proxy defs */

void *scm_proxy_init(void *context);
void scm_proxy_recv_ack(struct scm_packet *packet, void *context);
void scm_proxy_recv_close(struct scm_packet *packet, void *inst);
int scm_proxy_connect_socket(int local_id, struct sockaddr *addr, int alen,
	void *context);
int scm_proxy_open_socket(int local_id, void *context);
void scm_proxy_close_socket(int local_id, void *context);

#endif

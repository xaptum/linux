// SPDX-License-Identifier: GPL-2.0+
/*
 * f_scm.c -- USB Socket Control Model (SCM) function driver
 *
 * Copyright (C) 2018-2019 Xaptum, Inc.
 */
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/device.h>
#include <linux/usb/composite.h>
#include <linux/xscm.h>
#include <linux/mutex.h>
#include <linux/net.h>
#include <net/sock.h>
#include <linux/spinlock.h>

#include "u_scm.h"
#include "u_f.h"

/*
 * The Socket Control Model is protocol for a USB device to manage and use
 * Berkeley/POSIX-style sockets on the host.  It allows the device to
 * communicate with remote servers using the network connection of the host.
 * Currently supported protocols include TCP/IPv4 and TCP/IPv6.
 *
 * The SCM data transfer model uses bulk endpoints (short packet terminated)
 * to send and recieve data from the hosts sockets and interrupt endpoints to
 * communcate socket management data (open, connect, ect).
 */

/*
 * Change to your devices appropiate value and add an entry to the host drivers
 * device table
 */
#define SCM_SUBCLASS 0xab
#define MAX_INT_PACKET_SIZE    64
#define SCM_STATUS_INTERVAL_MS 4 //32
#define SCM_ACK_TIMEOUT 10000

/**
 * Usb function structure definition
 */
struct f_scm {
	struct usb_function function;

	struct usb_ep *bulk_in;
	struct usb_ep *bulk_out;
	struct usb_ep *cmd_out;
	struct usb_ep *cmd_in;
	struct usb_ep *ep0;

	struct usb_request	*req_in;
	struct usb_request	*req_out;
	struct usb_request	*req_bulk_out;

	void *proxy_context;
};

/* Forward declarations */
static void scm_send_int_msg_complete(struct usb_ep *ep, struct usb_request *req);
static int scm_read_out_cmd(struct f_scm *scm_inst);
static int scm_read_out_bulk(struct f_scm *scm_inst);
void scm_proxy_recv_transmit(struct scm_packet *packet, void *inst);

/* Socket extern defs */
extern int xaprc00x_register(void *proxy_context);
extern void xaprc00x_sock_connect_ack(int sock_id, struct scm_packet *packet);
extern void xaprc00x_sock_open_ack(int sock_id, struct scm_packet *ack);
extern void xaprc00x_sock_transmit(int sock_id, void *data, int len);
extern int xaprc00x_sock_handle_host_side_shutdown(int sock_id, int how);
/*
 * The USB interface descriptor to tell the host
 * how many endpoints are being deviced, ect.
 */
static struct usb_interface_descriptor scm_intf = {
	.bLength            = sizeof(scm_intf),
	.bDescriptorType    = USB_DT_INTERFACE,

	.bNumEndpoints      = 4,
	.bInterfaceClass    = USB_CLASS_VENDOR_SPEC,
	.bInterfaceSubClass = SCM_SUBCLASS,
	/* .bInterfaceNumber = DYNAMIC */
	/* .iInterface = DYNAMIC */
};

/***************************************************************************
 * USB DESCRIPTOR DEFINITIONS
 * There are 4 descriptors:
 *   Bulk In / Out
 *   Cmd In / Out
 * There are 3 speeds:
 *   Full Speed
 *   High Speed
 *   Super Speed
 * Every combination of the above needs its own descriptor.
 ***************************************************************************/

/**
 * Full speed endpoint descriptors
 */
static struct usb_endpoint_descriptor
fs_scm_cmd_in_desc = {
	.bLength =          USB_DT_ENDPOINT_SIZE,
	.bDescriptorType =  USB_DT_ENDPOINT,

	.bEndpointAddress = USB_DIR_IN,
	.bmAttributes =     USB_ENDPOINT_XFER_INT,
	.wMaxPacketSize =   cpu_to_le16(MAX_INT_PACKET_SIZE),
	.bInterval =        10,
};

static struct usb_endpoint_descriptor
fs_scm_cmd_out_desc = {
	.bLength =          USB_DT_ENDPOINT_SIZE,
	.bDescriptorType =  USB_DT_ENDPOINT,

	.bEndpointAddress = USB_DIR_OUT,
	.bmAttributes =     USB_ENDPOINT_XFER_INT,
	.wMaxPacketSize =   cpu_to_le16(MAX_INT_PACKET_SIZE),
	.bInterval =        10,
};

static struct usb_endpoint_descriptor fs_scm_in_desc = {
	.bLength =          USB_DT_ENDPOINT_SIZE,
	.bDescriptorType =  USB_DT_ENDPOINT,

	.bEndpointAddress = USB_DIR_IN,
	.bmAttributes =     USB_ENDPOINT_XFER_BULK,

};

static struct usb_endpoint_descriptor fs_scm_out_desc =  {
	.bLength =          USB_DT_ENDPOINT_SIZE,
	.bDescriptorType =  USB_DT_ENDPOINT,

	.bEndpointAddress = USB_DIR_OUT,
	.bmAttributes =     USB_ENDPOINT_XFER_BULK,

};

static struct usb_descriptor_header *scm_fs_descs[] = {
	(struct usb_descriptor_header *) &scm_intf,
	(struct usb_descriptor_header *) &fs_scm_in_desc,
	(struct usb_descriptor_header *) &fs_scm_out_desc,
	(struct usb_descriptor_header *) &fs_scm_cmd_in_desc,
	(struct usb_descriptor_header *) &fs_scm_cmd_out_desc,
	NULL,
};

/**
 * High speed descriptors
 */
static struct usb_endpoint_descriptor
hs_scm_cmd_in_desc = {
	.bLength =          USB_DT_ENDPOINT_SIZE,
	.bDescriptorType =  USB_DT_ENDPOINT,

	.bEndpointAddress = USB_DIR_IN,
	.bmAttributes =     USB_ENDPOINT_XFER_INT,
	.wMaxPacketSize =   cpu_to_le16(MAX_INT_PACKET_SIZE),
	.bInterval =        USB_MS_TO_HS_INTERVAL(SCM_STATUS_INTERVAL_MS),
};

static struct usb_endpoint_descriptor
hs_scm_cmd_out_desc = {
	.bLength =          USB_DT_ENDPOINT_SIZE,
	.bDescriptorType =  USB_DT_ENDPOINT,

	.bEndpointAddress = USB_DIR_OUT,
	.bmAttributes =     USB_ENDPOINT_XFER_INT,
	.wMaxPacketSize =   cpu_to_le16(MAX_INT_PACKET_SIZE),
	.bInterval =        USB_MS_TO_HS_INTERVAL(SCM_STATUS_INTERVAL_MS),
};

static struct usb_endpoint_descriptor hs_scm_in_desc = {
	.bLength =              USB_DT_ENDPOINT_SIZE,
	.bDescriptorType =      USB_DT_ENDPOINT,

	.bEndpointAddress =     USB_DIR_IN,
	.bmAttributes =         USB_ENDPOINT_XFER_BULK,
	.wMaxPacketSize =       cpu_to_le16(512),
};

static struct usb_endpoint_descriptor hs_scm_out_desc = {
	.bLength =              USB_DT_ENDPOINT_SIZE,
	.bDescriptorType =      USB_DT_ENDPOINT,

	.bEndpointAddress =     USB_DIR_OUT,
	.bmAttributes =         USB_ENDPOINT_XFER_BULK,
	.wMaxPacketSize =       cpu_to_le16(512),
};

static struct usb_descriptor_header *scm_hs_descs[] = {
	(struct usb_descriptor_header *) &scm_intf,
	(struct usb_descriptor_header *) &hs_scm_out_desc,
	(struct usb_descriptor_header *) &hs_scm_in_desc,
	(struct usb_descriptor_header *) &hs_scm_cmd_out_desc,
	(struct usb_descriptor_header *) &hs_scm_cmd_in_desc,
	NULL,
};

/**
 * Superspeed descriptors
 */
static struct usb_endpoint_descriptor
ss_scm_cmd_in_desc = {
	.bLength =         USB_DT_ENDPOINT_SIZE,
	.bDescriptorType = USB_DT_ENDPOINT,

	.bEndpointAddress = USB_DIR_IN,
	.bmAttributes =     USB_ENDPOINT_XFER_INT,
	.wMaxPacketSize =   cpu_to_le16(MAX_INT_PACKET_SIZE),
	.bInterval =        USB_MS_TO_HS_INTERVAL(SCM_STATUS_INTERVAL_MS),
};

static struct usb_endpoint_descriptor
ss_scm_cmd_out_desc = {
	.bLength =         USB_DT_ENDPOINT_SIZE,
	.bDescriptorType = USB_DT_ENDPOINT,

	.bEndpointAddress = USB_DIR_OUT,
	.bmAttributes =     USB_ENDPOINT_XFER_INT,
	.wMaxPacketSize =   cpu_to_le16(MAX_INT_PACKET_SIZE),
	.bInterval =        USB_MS_TO_HS_INTERVAL(SCM_STATUS_INTERVAL_MS),
};

static struct usb_ss_ep_comp_descriptor ss_scm_cmd_comp_desc = {
	.bLength =		sizeof(ss_scm_cmd_comp_desc),
	.bDescriptorType =	USB_DT_SS_ENDPOINT_COMP,
	.wBytesPerInterval =	cpu_to_le16(MAX_INT_PACKET_SIZE),
};

static struct usb_endpoint_descriptor ss_scm_in_desc = {
	.bLength =              USB_DT_ENDPOINT_SIZE,
	.bDescriptorType =      USB_DT_ENDPOINT,

	.bEndpointAddress =     USB_DIR_IN,
	.bmAttributes =         USB_ENDPOINT_XFER_BULK,
	.wMaxPacketSize =       cpu_to_le16(1024),
};

static struct usb_ss_ep_comp_descriptor ss_scm_in_comp_desc = {
	.bLength =              USB_DT_SS_EP_COMP_SIZE,
	.bDescriptorType =      USB_DT_SS_ENDPOINT_COMP,
	.wBytesPerInterval =    0,
};

static struct usb_endpoint_descriptor ss_scm_out_desc = {
	.bLength =              USB_DT_ENDPOINT_SIZE,
	.bDescriptorType =      USB_DT_ENDPOINT,

	.bEndpointAddress =     USB_DIR_OUT,
	.bmAttributes =         USB_ENDPOINT_XFER_BULK,
	.wMaxPacketSize =       cpu_to_le16(1024),
};

static struct usb_ss_ep_comp_descriptor ss_scm_out_comp_desc = {
	.bLength =              USB_DT_SS_EP_COMP_SIZE,
	.bDescriptorType =      USB_DT_SS_ENDPOINT_COMP,
	.bMaxBurst =            0,
	.bmAttributes =         0,
	.wBytesPerInterval =    0,
};

static struct usb_descriptor_header *scm_ss_descs[] = {
	(struct usb_descriptor_header *) &scm_intf,

	(struct usb_descriptor_header *) &ss_scm_out_desc,
	(struct usb_descriptor_header *) &ss_scm_out_comp_desc,

	(struct usb_descriptor_header *) &ss_scm_in_desc,
	(struct usb_descriptor_header *) &ss_scm_in_comp_desc,

	(struct usb_descriptor_header *) &ss_scm_cmd_in_desc,
	(struct usb_descriptor_header *) &ss_scm_cmd_comp_desc,

	(struct usb_descriptor_header *) &ss_scm_cmd_out_desc,
	(struct usb_descriptor_header *) &ss_scm_cmd_comp_desc,
	NULL,
};

/**
 * USB string definitions
 */
static struct usb_string scm_string_defs[] = {
	[0].s = "Socket Control Model (SCM)",
	{  }                    /* end of list */
};

static struct usb_gadget_strings scm_string_table = {
	.language = 0x0409, /* en-us */
	.strings =  scm_string_defs,
};

static struct usb_gadget_strings *scm_strings[] = {
	&scm_string_table,
	NULL,
};

/**
 * usb allocation
 */
static inline struct f_scm *func_to_scm(struct usb_function *f)
{
	return container_of(f, struct f_scm, function);
}

/* Binds this driver to a device */
static int scm_bind(struct usb_configuration *c, struct usb_function *f)
{
	struct usb_composite_dev *cdev;
	struct f_scm *scm;
	int id;
	int ret;

	cdev = c->cdev;
	scm = func_to_scm(f);

	id = usb_interface_id(c, f);
	if (id < 0)
		return -ENODEV;

	scm_intf.bInterfaceNumber = id;

	id = usb_string_id(cdev);
	if (id < 0)
		return -ENODEV;

	scm_string_defs[0].id = id;
	scm_intf.iInterface = id;

	/* Set up the bulk and command endpoints */
	scm->bulk_in = usb_ep_autoconfig(cdev->gadget, &fs_scm_in_desc);
	if (!scm->bulk_in) {
		ERROR(cdev, "%s: can't autoconfigure bulk source on %s\n",
			f->name, cdev->gadget->name);
		return -ENODEV;

	}

	scm->bulk_out = usb_ep_autoconfig(cdev->gadget, &fs_scm_out_desc);
	if (!scm->bulk_out) {
		ERROR(cdev, "%s: can't autoconfigure bulk sink on %s\n",
			f->name, cdev->gadget->name);
		return -ENODEV;

	}

	scm->cmd_out = usb_ep_autoconfig(cdev->gadget, &fs_scm_cmd_out_desc);
	if (!scm->cmd_out) {
		ERROR(cdev,
			"%s: can't autoconfigure control source on %s\n",
			f->name, cdev->gadget->name);
		return -ENODEV;
	}

	scm->cmd_in = usb_ep_autoconfig(cdev->gadget,
		&fs_scm_cmd_in_desc);
	if (!scm->cmd_in) {
		ERROR(cdev, "%s: can't autoconfigure control sink on %s\n",
		f->name, cdev->gadget->name);
		return -ENODEV;
	}


	/* support high speed hardware */
	hs_scm_out_desc.bEndpointAddress =
		fs_scm_out_desc.bEndpointAddress;
	hs_scm_in_desc.bEndpointAddress =
		fs_scm_in_desc.bEndpointAddress;
	hs_scm_cmd_out_desc.bEndpointAddress =
		fs_scm_cmd_out_desc.bEndpointAddress;
	hs_scm_cmd_in_desc.bEndpointAddress =
		fs_scm_cmd_in_desc.bEndpointAddress;

	/* support super speed hardware */
	ss_scm_out_desc.bEndpointAddress =
		fs_scm_out_desc.bEndpointAddress;
	ss_scm_in_desc.bEndpointAddress =
		fs_scm_in_desc.bEndpointAddress;
	ss_scm_cmd_out_desc.bEndpointAddress =
		fs_scm_cmd_out_desc.bEndpointAddress;
	ss_scm_cmd_in_desc.bEndpointAddress =
		fs_scm_cmd_in_desc.bEndpointAddress;

	/* Copy the descriptors to the function */
	ret = usb_assign_descriptors(f, scm_fs_descs, scm_hs_descs,
			scm_ss_descs, NULL);
	if (ret)
		goto fail;

	/* Initialize the proxy and store it's instance for future calls */
	scm->proxy_context = scm_proxy_init(scm);

	DBG(cdev, "SCM bind complete at %s speed\n",
		gadget_is_superspeed(c->cdev->gadget) ? "super" :
		gadget_is_dualspeed(c->cdev->gadget) ? "dual" : "full");
fail:
	return ret;
}

static void scm_free_func(struct usb_function *f)
{
	struct f_scm_opts *opts;

	opts = container_of(f->fi, struct f_scm_opts, func_inst);

	mutex_lock(&opts->lock);
	opts->refcnt--;
	mutex_unlock(&opts->lock);

	usb_free_all_descriptors(f);
	kfree(func_to_scm(f));
}

static int enable_endpoint(struct usb_composite_dev *cdev, struct f_scm *scm,
	struct usb_ep *ep)
{
	int result;

	result = config_ep_by_speed(cdev->gadget, &(scm->function), ep);
	if (result)
		goto out;

	result = usb_ep_enable(ep);
	if (result < 0)
		goto out;
	ep->driver_data = scm;
	result = 0;
out:
	return result;
}

static void disable_ep(struct usb_composite_dev *cdev, struct usb_ep *ep)
{
	int value;

	value = usb_ep_disable(ep);
	if (value < 0)
		DBG(cdev, "disable %s --> %d\n", ep->name, value);
}

static int enable_scm(struct usb_composite_dev *cdev, struct f_scm *scm)
{
	int result = 0;
	// Enable the endpoints
	result = enable_endpoint(cdev, scm, scm->bulk_in);
	if (result) {
		ERROR(cdev, "enable_endpoint for bulk_in failed ret=%d",
			result);
		goto exit;
	}

	result = enable_endpoint(cdev, scm, scm->bulk_out);
	if (result) {
		ERROR(cdev, "enable_endpoint for bulk_out failed ret=%d",
			result);
		goto exit_free_bi;
	}

	result = enable_endpoint(cdev, scm, scm->cmd_in);
	if (result) {
		ERROR(cdev, "enable_endpoint for cmd_in failed ret=%d",
			result);
		goto exit_free_bo;
	}

	result = enable_endpoint(cdev, scm, scm->cmd_out);
	if (result) {
		ERROR(cdev, "enable_endpoint for cmd_out failed ret=%d",
			result);
		goto exit_free_ci;
	}

	scm->req_in = alloc_ep_req(scm->cmd_in, MAX_INT_PACKET_SIZE);
	if (!scm->req_in) {
		ERROR(cdev, "alloc_ep_req for req_in failed");
		result = -ENOMEM;
		goto exit_free_co;
	}
	scm->req_in->context = scm;
	scm->req_in->complete = scm_send_int_msg_complete;

	/* TODO use a better size than +64 */
	scm->req_out = alloc_ep_req(scm->cmd_out, MAX_INT_PACKET_SIZE+64);
	if (!scm->req_out) {
		ERROR(cdev, "alloc_ep_req for req_out failed");
		result = -ENOMEM;
		goto exit_free_ri;
	}

	scm->req_bulk_out = alloc_ep_req(scm->bulk_out, 2048);
	if (!scm->req_bulk_out) {
		ERROR(cdev, "alloc_ep_req for req_bulk_out failed");
		result = -ENOMEM;
		goto exit_free_ri;
	}

	scm_read_out_cmd(scm);
	scm_read_out_bulk(scm);

	goto exit;
exit_free_ri:
	free_ep_req(scm->cmd_in, scm->req_in);
	scm->req_in = NULL;
exit_free_co:
	disable_ep(cdev, scm->cmd_out);
exit_free_ci:
	disable_ep(cdev, scm->cmd_in);
exit_free_bo:
	disable_ep(cdev, scm->bulk_out);
exit_free_bi:
	disable_ep(cdev, scm->bulk_in);
exit:
	return result;
}

static void disable_scm(struct f_scm *scm)
{
	struct usb_composite_dev *cdev;

	if (scm->cmd_in && scm->req_in)
		free_ep_req(scm->cmd_in, scm->req_in);
	scm->req_in = NULL;

	cdev = scm->function.config->cdev;
	disable_ep(cdev, scm->bulk_in);
	disable_ep(cdev, scm->bulk_out);
	disable_ep(cdev, scm->cmd_in);
	disable_ep(cdev, scm->cmd_out);
}

/**
 * Sets the interface alt setting
 * As we have no alt settings yet value will be zero.
 * But interface should be disabled / enabled again
 */
static int scm_set_alt(struct usb_function *f, unsigned int intf,
	unsigned int alt)
{
	int ret;

	struct f_scm *scm = func_to_scm(f);
	struct usb_composite_dev *cdev = f->config->cdev;

	disable_scm(scm);
	ret = enable_scm(cdev, scm);
	if (ret)
		goto exit;

exit:
	return ret;
}

static void scm_disable(struct usb_function *f)
{
	struct f_scm *sock = func_to_scm(f);

	disable_scm(sock);
}

static struct usb_function *scm_alloc(struct usb_function_instance *fi)
{
	struct f_scm_opts *scm_opts;
	struct f_scm *scm;

	scm = kzalloc(sizeof(*scm), GFP_KERNEL);
	if (!scm)
		return ERR_PTR(-ENOMEM);

	scm_opts = container_of(fi, struct f_scm_opts, func_inst);

	mutex_lock(&scm_opts->lock);
	scm_opts->refcnt++;
	mutex_unlock(&scm_opts->lock);

	scm->function.name = "scm";
	scm->function.bind = scm_bind;
	scm->function.set_alt = scm_set_alt;
	scm->function.disable = scm_disable;
	scm->function.strings = scm_strings;

	scm->function.free_func = scm_free_func;

	return &scm->function;
}

/**
 *
 * usb instance allocation handling
 */
static inline struct f_scm_opts *to_f_scm_opts(struct config_item *item)
{
	return container_of(to_config_group(item), struct f_scm_opts,
		func_inst.group);
}

static void scm_attr_release(struct config_item *item)
{
	struct f_scm_opts *scm_opts = to_f_scm_opts(item);

	usb_put_function_instance(&scm_opts->func_inst);
}

static struct configfs_item_operations scm_item_ops = {
	.release                = scm_attr_release,
};

static struct configfs_attribute *scm_attrs[] = {
	NULL,
};

static struct config_item_type scm_func_type = {
		.ct_item_ops    = &scm_item_ops,
		.ct_attrs       = scm_attrs,
		.ct_owner       = THIS_MODULE,
};

static void scm_free_instance(struct usb_function_instance *fi)
{
	struct f_scm_opts *scm_opts;

	scm_opts = container_of(fi, struct f_scm_opts, func_inst);
	kfree(scm_opts);
}

static struct usb_function_instance *scm_alloc_inst(void)
{
	struct f_scm_opts *scm_opts;

	scm_opts = kzalloc(sizeof(*scm_opts), GFP_KERNEL);
	if (!scm_opts)
		return ERR_PTR(-ENOMEM);

	mutex_init(&scm_opts->lock);

	scm_opts->func_inst.free_func_inst = scm_free_instance;

	config_group_init_type_name(&scm_opts->func_inst.group, "",
		&scm_func_type);

	return &scm_opts->func_inst;
}

DECLARE_USB_FUNCTION(scm, scm_alloc_inst, scm_alloc);

static int __init f_scm_init(void)
{
	usb_function_register(&scmusb_func);
	return 0;
}

static void __exit f_scm_exit(void)
{
	usb_function_unregister(&scmusb_func);
}

module_init(f_scm_init);
module_exit(f_scm_exit);

/* Handle USB listening and writing */
static void scm_send_int_msg_complete(struct usb_ep *ep, struct usb_request *req)
{
	kfree(req->buf);
}
static void scm_send_int_msg(void *data, int len, struct f_scm *scm_inst)
{
	struct usb_request *req = scm_inst->req_in;
	int ret;

	if (!req)
		return;

	req->buf = kmalloc(MAX_INT_PACKET_SIZE, GFP_ATOMIC);
	memcpy(req->buf, data, len);
	req->length = len;
	ret = usb_ep_queue(scm_inst->cmd_in, scm_inst->req_in, GFP_ATOMIC);
}

static void scm_send_bulk_msg_complete(struct usb_ep *ep, struct usb_request *req)
{
	kfree(req->buf);
	usb_ep_free_request(ep, req);
}

static void scm_send_bulk_msg(struct scm_packet_hdr *hdr, void *data, int len,
	struct f_scm *scm_inst)
{
	struct usb_request *in_req;
	void *usb_data;
	int total_packet_len = sizeof(*hdr) + len;

	in_req = usb_ep_alloc_request(scm_inst->bulk_in, GFP_KERNEL);
	in_req->length = total_packet_len;
	in_req->complete = scm_send_bulk_msg_complete;

	usb_data = kmalloc(total_packet_len, GFP_KERNEL);
	in_req->buf = usb_data;
	memcpy(in_req->buf, hdr, sizeof(*hdr));
	memcpy(in_req->buf + sizeof(*hdr), data, len);

	usb_ep_queue(scm_inst->bulk_in, in_req, GFP_ATOMIC);
}

/* Reads SCM command from the host */
static void scm_process_out_cmd(struct scm_packet *packet, size_t len,
	struct f_scm *usb_context)
{
	/**
	 *Make sure the packet is big enough for the packet and payload
	 * (checked in order to avoid reading bad memory)
	 */
	if (!packet || len < sizeof(*packet) ||
		len > (sizeof(*packet)+packet->hdr.payload_len))
		return;

	/* Incoming command is either a close notificaiton or ACK */
	switch (packet->hdr.opcode) {
	case SCM_OP_ACK:
		scm_proxy_recv_ack(packet, usb_context->proxy_context);
		break;
	case SCM_OP_CLOSE:
		scm_proxy_recv_close(packet, usb_context->proxy_context);
		break;
	default:
		pr_err("%s got unexpected packet %d",
			__func__, packet->hdr.opcode);
		break;
	}
}
static void scm_read_out_cmd_cb(struct usb_ep *ep, struct usb_request *req)
{
	if (req->buf)
		scm_process_out_cmd(req->buf, req->actual, req->context);
	scm_read_out_cmd(req->context);
}
static int scm_read_out_cmd(struct f_scm *scm_inst)
{
	struct usb_request *out_req = scm_inst->req_out;

	out_req->length = sizeof(struct scm_packet) + 64;
	out_req->buf = kmalloc(out_req->length, GFP_ATOMIC);
	out_req->dma = 0;
	out_req->complete = scm_read_out_cmd_cb;
	out_req->context = scm_inst;
	usb_ep_queue(scm_inst->cmd_out, out_req, GFP_ATOMIC);

	return 0;
}

static void scm_process_out_data(struct scm_packet *packet, size_t len,
	struct f_scm *usb_context)
{
	/**
	 *Make sure the packet is big enough for the packet and payload
	 * (checked in order to avoid reading bad memory)
	 */
	if (!packet || len < sizeof(struct scm_packet_hdr) ||
		len > (sizeof(struct scm_packet_hdr)+packet->hdr.payload_len)) {
		return;
	}

	/* Incoming command is either a close notificaiton or ACK */
	switch (packet->hdr.opcode) {
	case SCM_OP_TRANSMIT:
		scm_proxy_recv_transmit(packet, usb_context->proxy_context);
		break;
	default:
		pr_err("%s got opcode %d", __func__, packet->hdr.opcode);
		break;
	}
}
static void scm_read_out_bulk_cb(struct usb_ep *ep, struct usb_request *req)
{
	if (req->buf) {
		scm_process_out_data(req->buf, req->actual, req->context);
		kfree(req->buf);
	}
	scm_read_out_bulk(req->context);
}
static int scm_read_out_bulk(struct f_scm *scm_inst)
{
	struct usb_request *out_bulk_req = scm_inst->req_bulk_out;

	out_bulk_req->length = 2048;
	out_bulk_req->buf = kmalloc(out_bulk_req->length, GFP_ATOMIC);
	out_bulk_req->dma = 0;
	out_bulk_req->complete = scm_read_out_bulk_cb;
	out_bulk_req->context = scm_inst;
	usb_ep_queue(scm_inst->bulk_out, out_bulk_req, GFP_ATOMIC);
	return 0;
}


/* SCM Proxy */
/* This definately has to be moved somewhere else */
MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Daniel Berliner");
MODULE_DESCRIPTION("SCM Driver");
MODULE_VERSION("0.0.1");


/* SCM Proxy internal functions */
struct scm_proxy_inst {
	void *usb_context;
	atomic_t scm_msg_id;
	spinlock_t ack_list_lock;
	struct workqueue_struct *ack_wq;
	struct workqueue_struct *data_wq;
	struct list_head ack_list;
};

struct scm_proxy_work {
	struct work_struct work;
	void *proxy_context;
	struct scm_packet *packet;
};

/* For naming the ACK workqueue */
static atomic_t g_proxy_counter;

/**
 * scm_proxy_get_msg_id - Gets a unique message ID for outgoing messages
 *
 * @proxy_context The SCM proxy context
 *
 * Returns: Unique message ID
 *
 */
static int scm_proxy_get_msg_id(struct scm_proxy_inst *proxy_context)
{
	__u16 id;
	/*
	 * Note: This operation is defined in the Kernel as 2s compliment
	 * overflow (INT_MAX+1==INT_MIN) becuase the kernel uses
	 * -fno-strict-overflow
	 */
	id = atomic_inc_return(&proxy_context->scm_msg_id);
	return id;
}

/**
 * scm_proxy_assign_ip4 - Assign an IPv4 address to an SCM packet
 *
 * @packet The packet being written to
 * @addr The socket address
 *
 * Fills the packets connect member to the information given in the
 * addr parameter.
 *
 */
static void scm_proxy_assign_ip4(struct scm_packet *packet,
	struct sockaddr *addr)
{
	struct sockaddr_in *ip4_addr = (struct sockaddr_in *) addr;

	packet->connect.addr.ip4.ip_addr = ip4_addr->sin_addr.s_addr;
	packet->connect.port = ip4_addr->sin_port;
	packet->connect.family = SCM_FAM_IP;

	packet->hdr.payload_len = sizeof(struct scm_payload_connect_ip) -
		sizeof(union scm_payload_connect_ip_addr) +
		sizeof(struct scm_payload_connect_ip4);
}

/**
 * scm_proxy_assign_ip6 - Assign an IPv6 address to an SCM packet
 *
 * @packet The packet being written to
 * @addr The socket address
 *
 * Fills the packets connect member to the information given in the
 * addr parameter.
 *
 */
static void scm_proxy_assign_ip6(struct scm_packet *packet,
	struct sockaddr *addr)
{
	struct sockaddr_in6 *ip6_addr = (struct sockaddr_in6 *) addr;

	memcpy(packet->connect.addr.ip6.ip_addr,
		&ip6_addr->sin6_addr, sizeof(struct in6_addr));
	packet->connect.port = ip6_addr->sin6_port;
	packet->connect.addr.ip6.scope_id = ip6_addr->sin6_scope_id;
	packet->connect.addr.ip6.flow_info = ip6_addr->sin6_flowinfo;
	packet->connect.family = SCM_FAM_IP6;

	packet->hdr.payload_len = sizeof(struct scm_payload_connect_ip) -
		sizeof(union scm_payload_connect_ip_addr) +
		sizeof(struct scm_payload_connect_ip6);
}

static void xaprc00x_proxy_process_open_ack(struct work_struct *work)
{
	struct scm_proxy_work *work_data;

	work_data = (struct scm_proxy_work *)work;
	xaprc00x_sock_open_ack(work_data->packet->hdr.sock_id,
		work_data->packet);
	kfree(work);
}

static void xaprc00x_proxy_process_connect_ack(struct work_struct *work)
{
	struct scm_proxy_work *work_data;

	work_data = (struct scm_proxy_work *)work;
	xaprc00x_sock_connect_ack(work_data->packet->hdr.sock_id,
		work_data->packet);
	kfree(work);
}

/**
 * An incoming CLOSE packet means that the server has stopped talking to us so
 * we run a shutdown on our end.
 */
static void xaprc00x_proxy_process_close(struct work_struct *work)
{
	struct scm_proxy_work *work_data;

	work_data = (struct scm_proxy_work *) work;
	xaprc00x_sock_handle_host_side_shutdown(
		work_data->packet->hdr.sock_id, 2);

	/* Freed here becuase the handler has no use for the packet */
	kfree(work_data->packet);
	kfree(work_data);
}

static void xaprc00x_proxy_process_transmit(struct work_struct *work)
{
	struct scm_proxy_work *work_data;

	work_data = (struct scm_proxy_work *)work;
	xaprc00x_sock_transmit(work_data->packet->hdr.sock_id,
		&work_data->packet->scm_payload_none,
		work_data->packet->hdr.payload_len);
}

/* SCM Proxy API functions */
/**
 * scm_proxy_recv_ack - Recieves an ACK message
 *
 * @packet The packet to process
 * @context The SCM proxy context
 *
 * Processes an SCM ACK packet. The `packet` parameter may be modified or
 * free'd after this functions returns.
 *
 */
void scm_proxy_recv_ack(struct scm_packet *packet, void *inst)
{
	struct scm_proxy_work *new_work;
	struct scm_proxy_inst *proxy_inst;

	/* The work item will be cleared at thend of the job */
	new_work = kmalloc(sizeof(*new_work), GFP_ATOMIC);
	if (!new_work)
		return;
	new_work->proxy_context = inst;

	/**
	 * This packet will be freed when the socket no longer needs it
	 * which may be after the workqueue is done
	 */
	new_work->packet = kmalloc(sizeof(*packet), GFP_ATOMIC);
	if (!new_work->packet) {
		kfree(new_work);
		return;
	}
	memcpy(new_work->packet, packet, sizeof(*packet));

	proxy_inst = inst;

	/* Queue a work item to handle the incoming packet */
	switch (packet->ack.orig_opcode) {
	case SCM_OP_OPEN:
		INIT_WORK(&new_work->work, xaprc00x_proxy_process_open_ack);
		queue_work(proxy_inst->ack_wq, &new_work->work);
		break;
	case SCM_OP_CONNECT:
		INIT_WORK(&new_work->work, xaprc00x_proxy_process_connect_ack);
		queue_work(proxy_inst->ack_wq, &new_work->work);
		break;
	case SCM_OP_CLOSE: /* Device does not care if the host ACKs */
	default:
		kfree(new_work->packet);
		kfree(new_work);
		break;
	}
}
EXPORT_SYMBOL_GPL(scm_proxy_recv_ack);

void scm_proxy_recv_transmit(struct scm_packet *packet, void *inst)
{
	struct scm_proxy_work *new_work;
	struct scm_proxy_inst *proxy_inst;
	int data_packet_len;
	/* The work item will be cleared at thend of the job */

	new_work = kmalloc(sizeof(*new_work), GFP_ATOMIC);

	if (!new_work)
		return;

	new_work->proxy_context = inst;

	/**
	 * This packet will be freed when the socket no longer needs it
	 * which may be after the workqueue is done
	 */
	data_packet_len = sizeof(struct scm_packet_hdr) +
		packet->hdr.payload_len;
	new_work->packet = kmalloc(
		data_packet_len,
		GFP_ATOMIC);
	if (!new_work->packet) {
		kfree(new_work);
		return;
	}
	memcpy(new_work->packet, packet, data_packet_len);

	proxy_inst = inst;

	INIT_WORK(&new_work->work, xaprc00x_proxy_process_transmit);
	queue_work(proxy_inst->data_wq, &new_work->work);
}
EXPORT_SYMBOL_GPL(scm_proxy_recv_transmit);

/**
 * scm_proxy_recv_close - Recieves an CLOSE message
 *
 * @packet The packet to process
 * @context The SCM proxy context
 *
 * Processes an SCM CLOSE packet. The `packet` parameter may be modified or
 * free'd after this functions returns.
 *
 */
void scm_proxy_recv_close(struct scm_packet *packet, void *inst)
{
	struct scm_proxy_work *new_work;
	struct scm_proxy_inst *proxy_inst;

	/* The work item will be cleared at thend of the job */
	new_work = kmalloc(sizeof(*new_work), GFP_ATOMIC);
	if (!new_work)
		return;
	new_work->proxy_context = inst;

	/* CLOSE does not have any fields */
	new_work->packet = kmalloc(sizeof(*packet), GFP_ATOMIC);
	if (!new_work->packet) {
		kfree(new_work);
		return;
	}
	memcpy(new_work->packet, packet, sizeof(*packet));

	proxy_inst = inst;

	/* Queue a work item to handle the incoming packet */
	INIT_WORK(&new_work->work, xaprc00x_proxy_process_close);
	queue_work(proxy_inst->ack_wq, &new_work->work);
}
EXPORT_SYMBOL_GPL(scm_proxy_recv_close);
/**
 * scm_proxy_init - Initializes an instance of the SCM proxy
 *
 * @usb_context The USB context to link with this proxy instance
 *
 * Initializes an instance of the SCM proxy to allow the SCM USB driver to talk
 * to the SCM network driver. The pointer returned by this function must be
 * passed to all other exported proxy functions as the "proxy context" to allow
 * the proxy to know which instance the operation is being performed on.
 *
 * Returns: A pointer to the instance for this proxy.
 *
 */
void *scm_proxy_init(void *usb_context)
{
	struct scm_proxy_inst *proxy_inst;

	/* Create a name that can contain the counter */
	char scm_wq_name[sizeof("scm_wq_4294967296")];
	char scm_data_wq_name[sizeof("scm_data_wq_4294967296")];

	proxy_inst = kzalloc(sizeof(struct scm_proxy_inst), GFP_KERNEL);
	if (!proxy_inst)
		return NULL;
	proxy_inst->usb_context = usb_context;

	snprintf(scm_wq_name, sizeof(scm_wq_name), "scm_wq_%d",
		atomic_inc_return(&g_proxy_counter));
	snprintf(scm_wq_name, sizeof(scm_wq_name), "scm_data_wq_%d",
		atomic_inc_return(&g_proxy_counter));

	proxy_inst->ack_wq = create_workqueue(scm_wq_name);
	proxy_inst->data_wq = create_workqueue(scm_data_wq_name);

	spin_lock_init(&proxy_inst->ack_list_lock);
	INIT_LIST_HEAD(&proxy_inst->ack_list);

	/* Start up the Xaptum SCM socket module */
	xaprc00x_register(proxy_inst);

	return proxy_inst;
}
EXPORT_SYMBOL_GPL(scm_proxy_init);

/**
 * scm_proxy_connect_socket - Connect an SCM socket
 *
 * @local_id The ID of the socket to close
 * @addr The socket address
 * @alen Address length in bytes
 * @context The SCM proxy context
 *
 * Sends a command to the device to connect an SCM socket to a given address.
 *
 * Returns: 0 on success or returned SCM error code.
 *
 */
int scm_proxy_connect_socket(int local_id, struct sockaddr *addr, int alen,
	void *context)
{
	struct scm_packet *packet = kzalloc(sizeof(struct scm_packet),
		GFP_KERNEL);
	int ret;
	struct scm_payload_ack ack;
	struct scm_proxy_inst *proxy_inst;

	proxy_inst = context;

	packet->hdr.opcode = SCM_OP_CONNECT;
	packet->hdr.msg_id = scm_proxy_get_msg_id(context);
	packet->hdr.sock_id = local_id;

	if (addr->sa_family == AF_INET)
		scm_proxy_assign_ip4(packet, addr);
	else if (addr->sa_family == AF_INET6)
		scm_proxy_assign_ip6(packet, addr);

	scm_send_int_msg(packet,
		sizeof(struct scm_packet_hdr) + packet->hdr.payload_len,
		proxy_inst->usb_context);

	kfree(packet);

	return 0;
}
EXPORT_SYMBOL_GPL(scm_proxy_connect_socket);

/**
 * scm_proxy_open_socket - Open an SCM socket
 *
 * @local_id The ID of the new socket
 * @context The SCM proxy context
 *
 * Sends a command to the device to open an SCM socket.
 *
 * Returns: 0 on success or returned SCM error code. Writes the new sockets
 * local ID to *local_id
 *
 */
int scm_proxy_open_socket(int local_id, void *context)
{
	struct scm_packet *packet = kzalloc(sizeof(struct scm_packet),
		GFP_ATOMIC);
	int ret;
	struct scm_payload_ack ack;
	struct scm_proxy_inst *proxy_inst;

	proxy_inst = context;

	packet->hdr.opcode = SCM_OP_OPEN;
	packet->hdr.msg_id = scm_proxy_get_msg_id(proxy_inst);
	packet->hdr.payload_len = sizeof(struct scm_payload_open);
	packet->open.addr_family = SCM_FAM_IP;
	packet->open.protocol = SCM_PROTO_TCP;
	packet->open.type = SCM_TYPE_STREAM;
	packet->open.handle = local_id;

	scm_send_int_msg(packet, sizeof(struct scm_packet),
		proxy_inst->usb_context);

	return 0;
}
EXPORT_SYMBOL_GPL(scm_proxy_open_socket);


/**
 * scm_proxy_close_socket - Close a SCM socket on the host
 *
 * @local_id The ID of the socket to close
 * @context The SCM proxy context
 *
 * Sends a command to the device to close a SCM socket.
 *
 */
void scm_proxy_close_socket(int local_id, void *context)
{
	struct scm_packet *ack;
	struct scm_packet *packet = kzalloc(sizeof(struct scm_packet),
		GFP_KERNEL);
	struct scm_proxy_inst *proxy_inst;

	proxy_inst = context;

	packet->hdr.opcode = SCM_OP_CLOSE;
	packet->hdr.msg_id = scm_proxy_get_msg_id(context);
	packet->hdr.sock_id = local_id;
	packet->hdr.payload_len = 0;

	scm_send_int_msg(packet, sizeof(struct scm_packet_hdr),
		proxy_inst->usb_context);

	kfree(packet);
}
EXPORT_SYMBOL_GPL(scm_proxy_close_socket);

int scm_proxy_write_socket(int sock_id, void *msg, int len, void *context)
{
	struct scm_proxy_inst *proxy_inst;
	struct scm_packet_hdr packet;

	proxy_inst = context;

	packet.opcode = SCM_OP_TRANSMIT;
	packet.msg_id = scm_proxy_get_msg_id(context);
	packet.sock_id = sock_id;
	packet.payload_len = len;

	scm_send_bulk_msg(&packet, msg, len,
		proxy_inst->usb_context);
	return len;
}
EXPORT_SYMBOL_GPL(scm_proxy_write_socket);

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

/* Forward declarations */
static void scm_proxy_recv_msg(void *msg, int len);
static void scm_proxy_init(void);
static void scm_send_msg_complete(struct usb_ep *ep, struct usb_request *req);
static int scm_read_out_cmd(void);
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
};
struct scm_packet_list_entry {
	struct scm_packet *packet;
	struct list_head list_handle;
};

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
	printk(KERN_INFO "enable_scm");
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
	scm->req_in->complete = scm_send_msg_complete;

	/* TODO use a better size than +64 */
	scm->req_out = alloc_ep_req( scm->cmd_out, MAX_INT_PACKET_SIZE+64 );
	if (!scm->req_out) {
		ERROR(cdev, "alloc_ep_req for req_out failed");
		result = -ENOMEM;
		goto exit_free_ri;
	}

	scm_read_out_cmd(scm);

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

	scm_proxy_init(scm);

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
static void scm_send_msg_complete(struct usb_ep *ep, struct usb_request *req)
{
} 
static void scm_send_msg(void *data, int len, struct f_scm scm_inst)
{
	struct usb_request *req = scm_inst->req_in;
	int ret;
	if (!req) {
		return;
	}
	req->buf = kmalloc(MAX_INT_PACKET_SIZE, GFP_ATOMIC);
	memcpy(req->buf, data, len);
	req->length = len;
	ret = usb_ep_queue(scm_inst->cmd_in, scm_inst->req_in, GFP_ATOMIC);
}

/* Reads SCM command from the host */
static void scm_process_out_cmd(struct scm_packet *packet, size_t len,
	struct scm_proxy_inst *inst)
{
	/* Make sure the packet is big enough for the packet and payload
	 * (checked in order to avoid reading bad memory) */
	if(!packet || len < sizeof(*packet) || 
		len < (sizeof(*packet)+packet->hdr.payload_len))
		return;

	/* Incoming command is either a close notificaiton or ACK */
	switch (packet->hdr.opcode) {
	case SCM_OP_ACK:
		printk("scm_process_out_cmd ACK");
		scm_notify_ack(packet, inst);
		break;
	case SCM_OP_CLOSE:
		/* No current implementation */
		printk("scm_process_out_cmd CLOSE");
		break;
	default:
		printk("scm_process_out_cmd UNSUPPORTED");
		break;
	}
}
static void scm_read_out_cmd_cb(struct usb_ep *ep, struct usb_request *req)
{
	if (req->buf) {
		scm_process_out_cmd(req->buf, req->actual, req->context);
	}
	scm_read_out_cmd(req->context);
}
static int scm_read_out_cmd(struct f_scm scm_inst)
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


MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Daniel Berliner");
MODULE_DESCRIPTION("SCM Driver");
MODULE_VERSION("0.0.1");

/* SCM Proxy.*/
/* This probably isnt the final place this code will be placed */
struct scm_proxy_inst {
	void *usb_context;
	__u8 scm_msg_id;
	struct mutex scm_msg_id_mutex;
	static wait_queue_head_t ack_wait_queue;
	struct list_head *ack_list;
};

static void scm_notify_ack(struct scm_packet *packet,
	struct scm_proxy_inst *inst)
{
	struct scm_packet_list_entry *entry = 
		kmalloc(sizeof(struct scm_packet_list_entry),
			GFP_ATOMIC);
	INIT_LIST_HEAD( &entry->list_handle );
	entry->packet = packet;
	list_add(&inst->ack_list, &entry->list_handle);
	wake_up(&ack_list->ack_wait_queue);
}

static struct scm_packet *ack_list_pop_by_id(int id,
	struct scm_proxy_inst *inst)
{
	struct list_head *position = NULL;
	list_for_each(position, &inst->ack_list)
	{
		struct scm_packet_list_entry *entry = 
			list_entry(position, struct scm_packet_list_entry,
				list_handle);
		struct scm_packet *msg = entry->packet;
		if (msg->hdr.msg_id == id)
		{
			list_del(&entry->list_handle);
			return msg;
		}
	}
	return NULL;
}


/* Global for now but will be localized when we need to support other devices.
 * The idea of making this global instead of the USB instance is that the proxy
 * manages the USB device, the USB parts shouldn't know the proxy context.
 */
struct scm_proxy_inst g_scm_proxy_inst = NULL;

/* Stubs for now */
struct scm_payload_ack scm_proxy_wait_ack(int msg_id)
{
	struct scm_packet *ack;
	struct scm_payload_ack empty = {0};
	wait_event_timeout(scm_ack_wait_queue,
		((ack = ack_list_pop_by_id(msg_id))!=NULL), SCM_ACK_TIMEOUT);

	if (ack) {
		printk(KERN_INFO "scm_proxy_wait_ack ack:");
		print_hex_dump(KERN_INFO, "", DUMP_PREFIX_OFFSET,
			16, 1, &ack->ack, sizeof(ack), true);
	} else {
		return empty;
	}
	return ack->ack;
}
EXPORT_SYMBOL_GPL(scm_proxy_wait_ack);


/* Copies an in msg for use in the proxy */
static void scm_proxy_recv_msg(void *msg, int len)
{
	printk(KERN_INFO "USB->Proxy:");
	print_hex_dump(KERN_INFO, "", DUMP_PREFIX_OFFSET,
		16, 1, msg, len, true);
}

static void scm_proxy_init(void *context)
{
	printk(KERN_INFO "scm_proxy_init");
	g_scm_proxy_inst = kzalloc(sizeof(struct scm_proxy_inst), GFP_KERNEL);
	if (!g_scm_proxy_inst)
		return;
	mutex_init(&g_scm_proxy_inst->scm_msg_id_mutex);
	init_waitqueue_head(&g_scm_proxy_inst->scm_ack_wait_queue);
	g_scm_proxy_inst->usb_context = context;
	g_scm_proxy_inst->scm_msg_id = 0;
}

static int scm_proxy_get_msg_id(void)
{
	int id;
	mutex_lock(&scm_msg_id_mutex);
	id = scm_msg_id++;
	mutex_unlock(&scm_msg_id_mutex);
	return id;
}

static void scm_proxy_assign_ip4(struct scm_packet *packet,
	struct sockaddr *addr)
{
	struct sockaddr_in *ip4_addr = (struct sockaddr_in*) addr;

	packet->connect.addr.ip4.ip_addr = ip4_addr->sin_addr.s_addr;
	packet->connect.port = ip4_addr->sin_port;
	packet->connect.family = SCM_FAM_IP;

	packet->hdr.payload_len = sizeof(struct scm_payload_connect_ip) -
		sizeof(union scm_payload_connect_ip_addr) +
		sizeof(struct scm_payload_connect_ip4);
}

static void scm_proxy_assign_ip6(struct scm_packet *packet,
	struct sockaddr *addr)
{
	struct sockaddr_in6 *ip6_addr = (struct sockaddr_in6*) addr;

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
int scm_proxy_connect_socket(int local_id, struct sockaddr *addr)
{
	struct scm_packet *packet = kzalloc(sizeof(struct scm_packet), GFP_KERNEL);
	int ret;
	struct scm_payload_ack ack;

	packet->hdr.opcode = SCM_OP_CONNECT;
	packet->hdr.msg_id = scm_proxy_get_msg_id();

	if (addr->sa_family == AF_INET)
		scm_proxy_assign_ip4(packet, addr);
	else if (addr->sa_family == AF_INET6)
		scm_proxy_assign_ip6(packet, addr);

	scm_send_msg(packet,
		sizeof(struct scm_packet_hdr) + packet->hdr.payload_len,
		g_scm_proxy_inst->usb_context);

	printk(KERN_INFO "Sent to USB (CONN)");
	print_hex_dump(KERN_INFO, "", DUMP_PREFIX_OFFSET,
		16, 1, packet, sizeof(struct scm_packet_hdr) +
		packet->hdr.payload_len, true);

	ack = scm_proxy_wait_ack(packet->hdr.msg_id);
	ret = ack.connect;

	kfree(packet);

	return ret;
}
EXPORT_SYMBOL_GPL(scm_proxy_connect_socket);

int scm_proxy_open_socket(int *local_id)
{
	struct scm_packet *packet = kzalloc(sizeof(struct scm_packet), GFP_ATOMIC);
	int ret;
	struct scm_payload_ack ack;

	packet->hdr.opcode = SCM_OP_OPEN;
	packet->hdr.msg_id = scm_proxy_get_msg_id();
	packet->hdr.payload_len = sizeof(struct scm_payload_open);
	packet->open.addr_family = SCM_FAM_IP;
	packet->open.protocol = SCM_PROTO_TCP;
	packet->open.type = SCM_TYPE_STREAM;

	scm_send_msg(packet, sizeof(struct scm_packet),
		g_scm_proxy_inst->usb_context);

	printk(KERN_INFO "scm_proxy_open_socket sent:");
	print_hex_dump(KERN_INFO, "", DUMP_PREFIX_OFFSET,
		16, 1, packet, sizeof(struct scm_packet_hdr) +
		packet->hdr.payload_len, true);
	ack = scm_proxy_wait_ack(packet->hdr.msg_id);

	ret = ack.open.code;
	if (ret == 0) {
		printk(KERN_INFO "scm_proxy_open_socket assigning sock id");
		*local_id = ack.open.sock_id;
	}

	kfree(packet);
	return ret;
}
EXPORT_SYMBOL_GPL(scm_proxy_open_socket);

void scm_proxy_close_socket(int local_id)
{
	struct scm_packet *ack;
	struct scm_packet *packet = kzalloc(sizeof(struct scm_packet), GFP_KERNEL);

	packet->hdr.opcode = SCM_OP_CLOSE;
	packet->hdr.msg_id = scm_proxy_get_msg_id();
	packet->hdr.payload_len = 0;

	scm_send_msg(packet, sizeof(struct scm_packet_hdr),
		g_scm_proxy_inst->usb_context);

	printk(KERN_INFO "Sent to USB (CLOSE) sent:");
	print_hex_dump(KERN_INFO, "", DUMP_PREFIX_OFFSET,
		16, 1, packet, sizeof(struct scm_packet_hdr), true);

	scm_proxy_wait_ack(packet->hdr.msg_id);
	kfree(packet);
	return;
}
EXPORT_SYMBOL_GPL(scm_proxy_close_socket);
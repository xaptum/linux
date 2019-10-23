// SPDX-License-Identifier: GPL-2.0+
/*
 * f_scm.c -- USB Socket Control Module (SCM) function driver
 *
 * Copyright (C) 2018-2019 Xaptum, Inc.
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/device.h>
#include <linux/usb/composite.h>
#include "u_scm.h"

/*
 * This function is a "Socket Control Module" (SCM) link. The purpose of
 * SCM is to allow a device to manage and communicate over socekts on its
 * host. SCMs data transfer model uses bulk endpoints (short packet terminated)
 * to send and recieve data from the hosts sockets and interrupt endpoints to
 * communcate socket management data (open, connect, ect).
 */

#define MAX_INT_PACKET_SIZE 64

/**
 * Usb function structure definition
 */
struct f_scm {
	struct usb_function     function;

	struct usb_composite_dev *cdev;

        struct usb_ep           *bulk_in_ep;
        struct usb_ep           *bulk_out_ep;
        struct usb_ep           *cmd_out_ep;
        struct usb_ep           *cmd_in_ep;
        struct usb_ep 		*ep0;
};

// @todo check for better way to keep this info as this makes it impossible to use more then one instnace

/*
 * The USB interface descriptor to tell the host
 * how many endpoints are being deviced, ect.
 */
static struct usb_interface_descriptor scm_intf = {
	.bLength = sizeof(scm_intf),
	.bDescriptorType = USB_DT_INTERFACE,
	.bNumEndpoints = 4,
	.bInterfaceClass = USB_CLASS_VENDOR_SPEC,
	.bInterfaceSubClass = 0xab,
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
static struct usb_endpoint_descriptor
f_scm_fs_ctrl_sink_desc = {
	.bLength         = USB_DT_ENDPOINT_SIZE,
	.bDescriptorType = USB_DT_ENDPOINT,

	.bEndpointAddress = USB_DIR_OUT,
	.bmAttributes    = USB_ENDPOINT_XFER_INT,
	.wMaxPacketSize  = cpu_to_le16(MAX_INT_PACKET_SIZE),
	.bInterval	 = 32,
};

static struct usb_endpoint_descriptor
f_scm_fs_ctrl_source_desc  = {
	.bLength         = USB_DT_ENDPOINT_SIZE,
	.bDescriptorType = USB_DT_ENDPOINT,

	.bEndpointAddress = USB_DIR_IN,
	.bmAttributes    = USB_ENDPOINT_XFER_INT,
	.wMaxPacketSize  = cpu_to_le16(MAX_INT_PACKET_SIZE),
	.bInterval 	 = 32,
};

static struct usb_endpoint_descriptor
f_scm_hs_ctrl_sink_desc = {
	.bLength         = USB_DT_ENDPOINT_SIZE,
	.bDescriptorType = USB_DT_ENDPOINT,

	.bEndpointAddress = USB_DIR_OUT,
	.bmAttributes    = USB_ENDPOINT_XFER_INT,
	.wMaxPacketSize  = cpu_to_le16(MAX_INT_PACKET_SIZE),
	.bInterval	 = USB_MS_TO_HS_INTERVAL(32),
};
static struct usb_endpoint_descriptor
f_scm_hs_ctrl_source_desc = {
	.bLength         = USB_DT_ENDPOINT_SIZE,
	.bDescriptorType = USB_DT_ENDPOINT,

	.bEndpointAddress = USB_DIR_IN,
	.bmAttributes    = USB_ENDPOINT_XFER_INT,
	.wMaxPacketSize  = cpu_to_le16(MAX_INT_PACKET_SIZE),
	.bInterval 	 = USB_MS_TO_HS_INTERVAL(32),
};


static struct usb_endpoint_descriptor
f_scm_ss_ctrl_sink_desc = {
	.bLength         = USB_DT_ENDPOINT_SIZE,
	.bDescriptorType = USB_DT_ENDPOINT,

	.bEndpointAddress = USB_DIR_OUT,
	.bmAttributes    = USB_ENDPOINT_XFER_INT,
	.wMaxPacketSize  = cpu_to_le16(MAX_INT_PACKET_SIZE),
	.bInterval	 = USB_MS_TO_HS_INTERVAL(32),
};
static struct usb_endpoint_descriptor
f_scm_ss_ctrl_source_desc = {
	.bLength         = USB_DT_ENDPOINT_SIZE,
	.bDescriptorType = USB_DT_ENDPOINT,

	.bEndpointAddress = USB_DIR_IN,
	.bmAttributes    = USB_ENDPOINT_XFER_INT,
	.wMaxPacketSize  = cpu_to_le16(MAX_INT_PACKET_SIZE),
	.bInterval 	 = USB_MS_TO_HS_INTERVAL(32),
};

/**
 * Full speed endpoint descriptors
 */
static struct usb_endpoint_descriptor f_scm_fs_bulk_source_desc =  {
	.bLength =              USB_DT_ENDPOINT_SIZE,
        .bDescriptorType =      USB_DT_ENDPOINT,

        .bEndpointAddress =     USB_DIR_IN,
        .bmAttributes =         USB_ENDPOINT_XFER_BULK,


};

static struct usb_endpoint_descriptor f_scm_fs_bulk_sink_desc = {
	.bLength =              USB_DT_ENDPOINT_SIZE,
        .bDescriptorType =      USB_DT_ENDPOINT,

        .bEndpointAddress =     USB_DIR_OUT,
        .bmAttributes =         USB_ENDPOINT_XFER_BULK,

};

static struct usb_descriptor_header *fs_scm_descs[] = {
 	(struct usb_descriptor_header *) &scm_intf,
        (struct usb_descriptor_header *) &f_scm_fs_bulk_sink_desc,
        (struct usb_descriptor_header *) &f_scm_fs_bulk_source_desc,
        (struct usb_descriptor_header *) &f_scm_fs_ctrl_sink_desc,
        (struct usb_descriptor_header *) &f_scm_fs_ctrl_source_desc,
        NULL,
};

/**
 * High speed descriptors
 */
static struct usb_endpoint_descriptor f_scm_hs_bulk_source_desc = {
        .bLength =              USB_DT_ENDPOINT_SIZE,
        .bDescriptorType =      USB_DT_ENDPOINT,

        .bmAttributes =         USB_ENDPOINT_XFER_BULK,
        .wMaxPacketSize =       cpu_to_le16(512),
};

static struct usb_endpoint_descriptor f_scm_hs_bulk_sink_desc = {
        .bLength =              USB_DT_ENDPOINT_SIZE,
        .bDescriptorType =      USB_DT_ENDPOINT,

        .bmAttributes =         USB_ENDPOINT_XFER_BULK,
        .wMaxPacketSize =       cpu_to_le16(512),
};

static struct usb_descriptor_header *hs_scm_descs[] = {
        (struct usb_descriptor_header *) &scm_intf,
        (struct usb_descriptor_header *) &f_scm_hs_bulk_source_desc,
        (struct usb_descriptor_header *) &f_scm_hs_bulk_sink_desc,
        (struct usb_descriptor_header *) &f_scm_hs_ctrl_source_desc,
        (struct usb_descriptor_header *) &f_scm_hs_ctrl_sink_desc,

        NULL,
};

/**
 * Superspeed descriptors
 */
static struct usb_endpoint_descriptor f_scm_ss_bulk_source_desc = {
        .bLength =              USB_DT_ENDPOINT_SIZE,
        .bDescriptorType =      USB_DT_ENDPOINT,

        .bmAttributes =         USB_ENDPOINT_XFER_BULK,
        .wMaxPacketSize =       cpu_to_le16(1024),
};

static struct usb_ss_ep_comp_descriptor f_scm_ss_bulk_source_comp_desc = {
        .bLength =              USB_DT_SS_EP_COMP_SIZE,
        .bDescriptorType =      USB_DT_SS_ENDPOINT_COMP,
        .bMaxBurst =            0,
        .bmAttributes =         0,
        .wBytesPerInterval =    0,
};

static struct usb_ss_ep_comp_descriptor f_scm_ss_ctrl_comp_desc = {
	.bLength =		sizeof f_scm_ss_ctrl_comp_desc,
	.bDescriptorType =	USB_DT_SS_ENDPOINT_COMP,

	/* the following 3 values can be tweaked if necessary */
	/* .bMaxBurst =		0, */
	/* .bmAttributes =	0, */
	.wBytesPerInterval =	cpu_to_le16(16),
};

static struct usb_endpoint_descriptor f_scm_ss_bulk_sink_desc = {
        .bLength =              USB_DT_ENDPOINT_SIZE,
        .bDescriptorType =      USB_DT_ENDPOINT,

        .bmAttributes =         USB_ENDPOINT_XFER_BULK,
        .wMaxPacketSize =       cpu_to_le16(1024),
};

static struct usb_ss_ep_comp_descriptor f_scm_ss_bulk_sink_comp_desc = {
        .bLength =              USB_DT_SS_EP_COMP_SIZE,
        .bDescriptorType =      USB_DT_SS_ENDPOINT_COMP,
        .bMaxBurst =            0,
        .bmAttributes =         0,
        .wBytesPerInterval =    0,
};

static struct usb_descriptor_header *ss_scm_descs[] = {
        (struct usb_descriptor_header *) &scm_intf,

        (struct usb_descriptor_header *) &f_scm_ss_bulk_source_desc,
        (struct usb_descriptor_header *) &f_scm_ss_bulk_source_comp_desc,

        (struct usb_descriptor_header *) &f_scm_ss_bulk_sink_desc,
        (struct usb_descriptor_header *) &f_scm_ss_bulk_sink_comp_desc,

        (struct usb_descriptor_header *) &f_scm_ss_ctrl_sink_desc,
        (struct usb_descriptor_header *) &f_scm_ss_ctrl_comp_desc,

        (struct usb_descriptor_header *) &f_scm_ss_ctrl_source_desc,
        (struct usb_descriptor_header *) &f_scm_ss_ctrl_comp_desc,
        NULL,
};

/**
 * USB string definitions
 */ 
static struct usb_string strings_scm[] = {
        [0].s = "scm interface",
        {  }                    /* end of list */
};

static struct usb_gadget_strings stringtab_scm = {
        .language       = 0x0409,       /* en-us */
        .strings        = strings_scm,
};

static struct usb_gadget_strings *scm_strings[] = {
        &stringtab_scm,
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
static int scm_bind( struct usb_configuration *c, struct usb_function *f)
{
	struct usb_composite_dev *cdev;
	struct f_scm *scm;
	int id;
	int ret;

	cdev = c->cdev;
	scm = func_to_scm(f);

	id = usb_interface_id(c,f);
	if (id < 0 )
		return -ENODEV;

	scm_intf.bInterfaceNumber = id;

	id = usb_string_id(cdev);
	if (id < 0 ) 
		return -ENODEV;


	strings_scm[0].id = id;
	scm_intf.iInterface = id;

	/* Set up the bulk and command endpoints */
	scm->bulk_in_ep = usb_ep_autoconfig(cdev->gadget, &f_scm_fs_bulk_source_desc );
	if (!scm->bulk_in_ep) {
	        printk(KERN_ERR "%s: can't autoconfigure bulk source on %s\n",
                        f->name, cdev->gadget->name);
                return -ENODEV;

	}

	scm->bulk_out_ep = usb_ep_autoconfig(cdev->gadget, &f_scm_fs_bulk_sink_desc );
	if (!scm->bulk_out_ep)
	{
		printk(KERN_ERR "%s: can't autoconfigure bulk sink on %s\n",
                        f->name, cdev->gadget->name);
                return -ENODEV;

	}

	scm->cmd_out_ep = usb_ep_autoconfig(cdev->gadget, &f_scm_fs_ctrl_sink_desc );
	if (!scm->cmd_out_ep)
	{
		printk(KERN_ERR "%s: can't autoconfigure control source on %s\n",
			f->name, cdev->gadget->name);
		return -ENODEV;
	}

	scm->cmd_in_ep = usb_ep_autoconfig(cdev->gadget, &f_scm_fs_ctrl_source_desc );
	if (!scm->cmd_in_ep)
	{
		printk(KERN_ERR "%s: can't autoconfigure control sink on %s\n",
		f->name, cdev->gadget->name);
		return -ENODEV;
	}

	/* support high speed hardware */
        f_scm_hs_bulk_source_desc.bEndpointAddress = f_scm_fs_bulk_source_desc.bEndpointAddress;
        f_scm_hs_bulk_sink_desc.bEndpointAddress   = f_scm_fs_bulk_sink_desc.bEndpointAddress;
	f_scm_hs_ctrl_source_desc.bEndpointAddress = f_scm_fs_ctrl_source_desc.bEndpointAddress;
	f_scm_hs_ctrl_sink_desc.bEndpointAddress   = f_scm_fs_ctrl_sink_desc.bEndpointAddress;
	
        /* support super speed hardware */
        f_scm_ss_bulk_source_desc.bEndpointAddress = f_scm_fs_bulk_source_desc.bEndpointAddress;
        f_scm_ss_bulk_sink_desc.bEndpointAddress   = f_scm_fs_bulk_sink_desc.bEndpointAddress;
	f_scm_ss_ctrl_source_desc.bEndpointAddress = f_scm_fs_ctrl_source_desc.bEndpointAddress;
	f_scm_ss_ctrl_sink_desc.bEndpointAddress   = f_scm_fs_ctrl_sink_desc.bEndpointAddress;

        /* Copy the descriptors to the function */
 	ret = usb_assign_descriptors(f, fs_scm_descs, hs_scm_descs,
                        ss_scm_descs, NULL);
 	if(ret<0)
 		return -ENOMEM;

	printk(KERN_INFO "SCM bind complete at %s speed\n",
				gadget_is_superspeed(c->cdev->gadget) ? "super" :
				gadget_is_dualspeed(c->cdev->gadget) ? "dual" : "full");
	return 0;
}

static void scm_free_func( struct usb_function *f )
{
	struct f_scm_opts *opts;
	
        opts = container_of(f->fi, struct f_scm_opts, func_inst);

        mutex_lock(&opts->lock);
        opts->refcnt--;
        mutex_unlock(&opts->lock);

        usb_free_all_descriptors(f);
        kfree(func_to_scm(f));
}

static int enable_endpoint( struct usb_composite_dev *cdev, struct f_scm *scm, struct usb_ep *ep )
{
	int result;

	result = config_ep_by_speed( cdev->gadget, &(scm->function), ep );

	result = usb_ep_enable(ep);

	ep->driver_data = scm;

	return 0;
}
/**
 * @todo add error out that disables endpoint when fail
 * @todo check if its better two use 2 functions for the complete part
 */
static int enable_scm( struct usb_composite_dev *cdev, struct f_scm *scm )
{
	int result = 0;

	printk(KERN_INFO "enable_scm enter");

	// Enable the endpoints
	result = enable_endpoint( cdev, scm, scm->bulk_in_ep );
	if(result)
		printk(KERN_ERR "enable_endpoint for bulk_in_ep failed ret=%d",result);

	result = enable_endpoint( cdev, scm, scm->bulk_out_ep );	
	if(result)
		printk(KERN_ERR "enable_endpoint for bulk_out_ep failed ret=%d",result);
	
	result = enable_endpoint( cdev, scm, scm->cmd_in_ep );
	if(result)
		printk(KERN_ERR "enable_endpoint for cmd_in_ep failed ret=%d",result);

	result = enable_endpoint( cdev, scm, scm->cmd_out_ep );	
	if(result)
		printk(KERN_ERR "enable_endpoint for cmd_out_ep failed ret=%d",result);

	// @todo check for better way to pass these structs
	scm->cdev = cdev;

	return result;
}

static void disable_scm(struct f_scm *scm )
{
	if(scm)
	{
		usb_ep_disable(scm->bulk_in_ep);
		usb_ep_disable(scm->bulk_out_ep);
		usb_ep_disable(scm->cmd_in_ep);
		usb_ep_disable(scm->cmd_out_ep);
	}
}



/**
 * Sets the interface alt setting
 * As we have no alt settings yet value will be zero.
 * But interface should be disabled / enabled again
 */
static int scm_set_alt( struct usb_function *f , unsigned intf, unsigned alt )
{
	int ret;

	struct f_scm	*scm = func_to_scm(f);
	struct usb_composite_dev *cdev = f->config->cdev;

	disable_scm(scm);
	ret = enable_scm(cdev, scm );
	return ret;
}

static void scm_disable(struct usb_function *f )
{
	struct f_scm	*sock = func_to_scm(f);

	disable_scm(sock);
}


static struct usb_function *scm_alloc(struct usb_function_instance *fi)
{
	struct f_scm_opts *scm_opts;
	struct f_scm *scm;

	scm = kzalloc( (sizeof *scm ), GFP_KERNEL );
	if ( !scm )
	{
		return ERR_PTR(-ENOMEM);
	}

	scm_opts = container_of(fi, struct f_scm_opts, func_inst );

	mutex_lock(&scm_opts->lock );
	scm_opts->refcnt++;
	mutex_unlock(&scm_opts->lock);

        scm->function.name = "scm";
        scm->function.bind = scm_bind;
        scm->function.set_alt = scm_set_alt;
        scm->function.disable = scm_disable;
        scm->function.strings = scm_strings;

        scm->function.free_func = scm_free_func;
	printk(KERN_INFO "scm_alloc exit");

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

	scm_opts = kzalloc( sizeof(*scm_opts ) , GFP_KERNEL );
	if ( !scm_opts )
	{
		return ERR_PTR(-ENOMEM);
	}

	mutex_init(&scm_opts->lock);

	scm_opts->func_inst.free_func_inst = scm_free_instance;

	config_group_init_type_name( &scm_opts->func_inst.group, "", &scm_func_type);

	return &scm_opts->func_inst;
}


DECLARE_USB_FUNCTION(scm, scm_alloc_inst, scm_alloc);

static int __init f_scm_init(void)
{
	usb_function_register( &scmusb_func );
	return 0;
}

static void __exit f_scm_exit(void)
{
	usb_function_unregister( &scmusb_func);
}

module_init( f_scm_init );
module_exit( f_scm_exit );

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Daniel Berliner");
MODULE_DESCRIPTION("Xaptum SCM Driver");
MODULE_VERSION("0.0.1");
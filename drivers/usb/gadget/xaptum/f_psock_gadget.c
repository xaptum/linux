/**
 * @file f_psock_gadget.c
 * @brief Usb gadget / composite framework integration for the f_psock kernel module
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/device.h>

#include <linux/usb/composite.h>

#define MAX_INT_PACKET_SIZE 64

/**************************************************************************
 *  f_psock structure definitions
 **************************************************************************/
struct f_psock_opts {
	struct usb_function_instance func_inst;
	struct mutex lock;
	int refcnt; 
};

/**
 * Usb function structure definition
 */
struct f_psock {
	struct usb_function     function;

        struct usb_ep           *bulk_in_ep;
        struct usb_ep           *bulk_out_ep;
        struct usb_ep           *cmd_out_ep;
        struct usb_ep           *cmd_in_ep;
        struct usb_ep 		*ep0;
};

// @todo check for better way to keep this info as this makes it impossible to use more then one instnace
static struct usb_composite_dev *w_cdev;
static struct f_psock *w_psock; 

/*
 * The USB interface descriptor to tell the host
 * how many endpoints are being deviced, ect.
 */
static struct usb_interface_descriptor psock_intf = {
	.bLength = sizeof(psock_intf),
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
f_psock_fs_ctrl_sink_desc = {
	.bLength         = USB_DT_ENDPOINT_SIZE,
	.bDescriptorType = USB_DT_ENDPOINT,

	.bEndpointAddress = USB_DIR_OUT,
	.bmAttributes    = USB_ENDPOINT_XFER_INT,
	.wMaxPacketSize  = cpu_to_le16(MAX_INT_PACKET_SIZE),
	.bInterval	 = 32,
};

static struct usb_endpoint_descriptor
f_psock_fs_ctrl_source_desc  = {
	.bLength         = USB_DT_ENDPOINT_SIZE,
	.bDescriptorType = USB_DT_ENDPOINT,

	.bEndpointAddress = USB_DIR_IN,
	.bmAttributes    = USB_ENDPOINT_XFER_INT,
	.wMaxPacketSize  = cpu_to_le16(MAX_INT_PACKET_SIZE),
	.bInterval 	 = 32,
};

static struct usb_endpoint_descriptor
f_psock_hs_ctrl_sink_desc = {
	.bLength         = USB_DT_ENDPOINT_SIZE,
	.bDescriptorType = USB_DT_ENDPOINT,

	.bEndpointAddress = USB_DIR_OUT,
	.bmAttributes    = USB_ENDPOINT_XFER_INT,
	.wMaxPacketSize  = cpu_to_le16(MAX_INT_PACKET_SIZE),
	.bInterval	 = USB_MS_TO_HS_INTERVAL(32),
};
static struct usb_endpoint_descriptor
f_psock_hs_ctrl_source_desc = {
	.bLength         = USB_DT_ENDPOINT_SIZE,
	.bDescriptorType = USB_DT_ENDPOINT,

	.bEndpointAddress = USB_DIR_IN,
	.bmAttributes    = USB_ENDPOINT_XFER_INT,
	.wMaxPacketSize  = cpu_to_le16(MAX_INT_PACKET_SIZE),
	.bInterval 	 = USB_MS_TO_HS_INTERVAL(32),
};


static struct usb_endpoint_descriptor
f_psock_ss_ctrl_sink_desc = {
	.bLength         = USB_DT_ENDPOINT_SIZE,
	.bDescriptorType = USB_DT_ENDPOINT,

	.bEndpointAddress = USB_DIR_OUT,
	.bmAttributes    = USB_ENDPOINT_XFER_INT,
	.wMaxPacketSize  = cpu_to_le16(MAX_INT_PACKET_SIZE),
	.bInterval	 = USB_MS_TO_HS_INTERVAL(32),
};
static struct usb_endpoint_descriptor
f_psock_ss_ctrl_source_desc = {
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
static struct usb_endpoint_descriptor f_psock_fs_bulk_source_desc =  {
	.bLength =              USB_DT_ENDPOINT_SIZE,
        .bDescriptorType =      USB_DT_ENDPOINT,

        .bEndpointAddress =     USB_DIR_IN,
        .bmAttributes =         USB_ENDPOINT_XFER_BULK,


};

static struct usb_endpoint_descriptor f_psock_fs_bulk_sink_desc = {
	.bLength =              USB_DT_ENDPOINT_SIZE,
        .bDescriptorType =      USB_DT_ENDPOINT,

        .bEndpointAddress =     USB_DIR_OUT,
        .bmAttributes =         USB_ENDPOINT_XFER_BULK,

};

static struct usb_descriptor_header *fs_psock_descs[] = {
 	(struct usb_descriptor_header *) &psock_intf,
        (struct usb_descriptor_header *) &f_psock_fs_bulk_sink_desc,
        (struct usb_descriptor_header *) &f_psock_fs_bulk_source_desc,
        (struct usb_descriptor_header *) &f_psock_fs_ctrl_sink_desc,
        (struct usb_descriptor_header *) &f_psock_fs_ctrl_source_desc,
        NULL,
};

/**
 * High speed descriptors
 */
static struct usb_endpoint_descriptor f_psock_hs_bulk_source_desc = {
        .bLength =              USB_DT_ENDPOINT_SIZE,
        .bDescriptorType =      USB_DT_ENDPOINT,

        .bmAttributes =         USB_ENDPOINT_XFER_BULK,
        .wMaxPacketSize =       cpu_to_le16(512),
};

static struct usb_endpoint_descriptor f_psock_hs_bulk_sink_desc = {
        .bLength =              USB_DT_ENDPOINT_SIZE,
        .bDescriptorType =      USB_DT_ENDPOINT,

        .bmAttributes =         USB_ENDPOINT_XFER_BULK,
        .wMaxPacketSize =       cpu_to_le16(512),
};

static struct usb_descriptor_header *hs_psock_descs[] = {
        (struct usb_descriptor_header *) &psock_intf,
        (struct usb_descriptor_header *) &f_psock_hs_bulk_source_desc,
        (struct usb_descriptor_header *) &f_psock_hs_bulk_sink_desc,
        (struct usb_descriptor_header *) &f_psock_hs_ctrl_source_desc,
        (struct usb_descriptor_header *) &f_psock_hs_ctrl_sink_desc,

        NULL,
};

/**
 * Superspeed descriptors
 */
static struct usb_endpoint_descriptor f_psock_ss_bulk_source_desc = {
        .bLength =              USB_DT_ENDPOINT_SIZE,
        .bDescriptorType =      USB_DT_ENDPOINT,

        .bmAttributes =         USB_ENDPOINT_XFER_BULK,
        .wMaxPacketSize =       cpu_to_le16(1024),
};

static struct usb_ss_ep_comp_descriptor f_psock_ss_bulk_source_comp_desc = {
        .bLength =              USB_DT_SS_EP_COMP_SIZE,
        .bDescriptorType =      USB_DT_SS_ENDPOINT_COMP,
        .bMaxBurst =            0,
        .bmAttributes =         0,
        .wBytesPerInterval =    0,
};

static struct usb_ss_ep_comp_descriptor f_psock_ss_ctrl_comp_desc = {
	.bLength =		sizeof f_psock_ss_ctrl_comp_desc,
	.bDescriptorType =	USB_DT_SS_ENDPOINT_COMP,

	/* the following 3 values can be tweaked if necessary */
	/* .bMaxBurst =		0, */
	/* .bmAttributes =	0, */
	.wBytesPerInterval =	cpu_to_le16(16),
};

static struct usb_endpoint_descriptor f_psock_ss_bulk_sink_desc = {
        .bLength =              USB_DT_ENDPOINT_SIZE,
        .bDescriptorType =      USB_DT_ENDPOINT,

        .bmAttributes =         USB_ENDPOINT_XFER_BULK,
        .wMaxPacketSize =       cpu_to_le16(1024),
};

static struct usb_ss_ep_comp_descriptor f_psock_ss_bulk_sink_comp_desc = {
        .bLength =              USB_DT_SS_EP_COMP_SIZE,
        .bDescriptorType =      USB_DT_SS_ENDPOINT_COMP,
        .bMaxBurst =            0,
        .bmAttributes =         0,
        .wBytesPerInterval =    0,
};

static struct usb_descriptor_header *ss_psock_descs[] = {
        (struct usb_descriptor_header *) &psock_intf,

        (struct usb_descriptor_header *) &f_psock_ss_bulk_source_desc,
        (struct usb_descriptor_header *) &f_psock_ss_bulk_source_comp_desc,

        (struct usb_descriptor_header *) &f_psock_ss_bulk_sink_desc,
        (struct usb_descriptor_header *) &f_psock_ss_bulk_sink_comp_desc,

        (struct usb_descriptor_header *) &f_psock_ss_ctrl_sink_desc,
        (struct usb_descriptor_header *) &f_psock_ss_ctrl_comp_desc,

        (struct usb_descriptor_header *) &f_psock_ss_ctrl_source_desc,
        (struct usb_descriptor_header *) &f_psock_ss_ctrl_comp_desc,
        NULL,
};

/**
 * USB string definitions
 */ 
static struct usb_string strings_psock[] = {
        [0].s = "psock interface",
        {  }                    /* end of list */
};

static struct usb_gadget_strings stringtab_psock = {
        .language       = 0x0409,       /* en-us */
        .strings        = strings_psock,
};

static struct usb_gadget_strings *psock_strings[] = {
        &stringtab_psock,
        NULL,
};


/**
 * usb allocation
 */
static inline struct f_psock *func_to_psock(struct usb_function *f)
{
        return container_of(f, struct f_psock, function);
}


/* Binds this driver to a device */
static int psock_bind( struct usb_configuration *c, struct usb_function *f)
{
	struct usb_composite_dev *cdev;
	struct f_psock *psock;
	int id;
	int ret;

	cdev = c->cdev;
	psock = func_to_psock(f);

	id = usb_interface_id(c,f);
	if (id < 0 )
		return -ENODEV;

	psock_intf.bInterfaceNumber = id;

	id = usb_string_id(cdev);
	if (id < 0 ) 
		return -ENODEV;


	strings_psock[0].id = id;
	psock_intf.iInterface = id;

	/* Set up the bulk and command endpoints */
	psock->bulk_in_ep = usb_ep_autoconfig(cdev->gadget, &f_psock_fs_bulk_source_desc );
	if (!psock->bulk_in_ep) {
	        printk(KERN_ERR "%s: can't autoconfigure bulk source on %s\n",
                        f->name, cdev->gadget->name);
                return -ENODEV;

	}

	psock->bulk_out_ep = usb_ep_autoconfig(cdev->gadget, &f_psock_fs_bulk_sink_desc );
	if (!psock->bulk_out_ep)
	{
		printk(KERN_ERR "%s: can't autoconfigure bulk sink on %s\n",
                        f->name, cdev->gadget->name);
                return -ENODEV;

	}

	psock->cmd_out_ep = usb_ep_autoconfig(cdev->gadget, &f_psock_fs_ctrl_sink_desc );
	if (!psock->cmd_out_ep)
	{
		printk(KERN_ERR "%s: can't autoconfigure control source on %s\n",
			f->name, cdev->gadget->name);
		return -ENODEV;
	}

	psock->cmd_in_ep = usb_ep_autoconfig(cdev->gadget, &f_psock_fs_ctrl_source_desc );
	if (!psock->cmd_in_ep)
	{
		printk(KERN_ERR "%s: can't autoconfigure control sink on %s\n",
		f->name, cdev->gadget->name);
		return -ENODEV;
	}

	/* support high speed hardware */
        f_psock_hs_bulk_source_desc.bEndpointAddress = f_psock_fs_bulk_source_desc.bEndpointAddress;
        f_psock_hs_bulk_sink_desc.bEndpointAddress   = f_psock_fs_bulk_sink_desc.bEndpointAddress;
	f_psock_hs_ctrl_source_desc.bEndpointAddress = f_psock_fs_ctrl_source_desc.bEndpointAddress;
	f_psock_hs_ctrl_sink_desc.bEndpointAddress   = f_psock_fs_ctrl_sink_desc.bEndpointAddress;
	
        /* support super speed hardware */
        f_psock_ss_bulk_source_desc.bEndpointAddress = f_psock_fs_bulk_source_desc.bEndpointAddress;
        f_psock_ss_bulk_sink_desc.bEndpointAddress   = f_psock_fs_bulk_sink_desc.bEndpointAddress;
	f_psock_ss_ctrl_source_desc.bEndpointAddress = f_psock_fs_ctrl_source_desc.bEndpointAddress;
	f_psock_ss_ctrl_sink_desc.bEndpointAddress   = f_psock_fs_ctrl_sink_desc.bEndpointAddress;

        /* Copy the descriptors to the function */
 	ret = usb_assign_descriptors(f, fs_psock_descs, hs_psock_descs,
                        ss_psock_descs, NULL);
 	if(ret<0)
 		return -ENOMEM;

	printk(KERN_INFO "SCM bind complete at %s speed\n",
				gadget_is_superspeed(c->cdev->gadget) ? "super" :
				gadget_is_dualspeed(c->cdev->gadget) ? "dual" : "full");
	return 0;
}

static void psock_free_func( struct usb_function *f )
{
	struct f_psock_opts *opts;
	
        opts = container_of(f->fi, struct f_psock_opts, func_inst);

        mutex_lock(&opts->lock);
        opts->refcnt--;
        mutex_unlock(&opts->lock);

        usb_free_all_descriptors(f);
        kfree(func_to_psock(f));
}

static int enable_endpoint( struct usb_composite_dev *cdev, struct f_psock *psock, struct usb_ep *ep )
{
	int result;

	result = config_ep_by_speed( cdev->gadget, &(psock->function), ep );

	result = usb_ep_enable(ep);

	ep->driver_data = psock;

	return 0;
}
/**
 * @todo add error out that disables endpoint when fail
 * @todo check if its better two use 2 functions for the complete part
 */
static int enable_psock( struct usb_composite_dev *cdev, struct f_psock *psock )
{
	int result = 0;

	printk(KERN_INFO "enable_psock enter");

	// Enable the endpoints
	result = enable_endpoint( cdev, psock, psock->bulk_in_ep );
	if(result)
		printk(KERN_ERR "enable_endpoint for bulk_in_ep failed ret=%d",result);

	result = enable_endpoint( cdev, psock, psock->bulk_out_ep );	
	if(result)
		printk(KERN_ERR "enable_endpoint for bulk_out_ep failed ret=%d",result);
	
	result = enable_endpoint( cdev, psock, psock->cmd_in_ep );
	if(result)
		printk(KERN_ERR "enable_endpoint for cmd_in_ep failed ret=%d",result);

	result = enable_endpoint( cdev, psock, psock->cmd_out_ep );	
	if(result)
		printk(KERN_ERR "enable_endpoint for cmd_out_ep failed ret=%d",result);

	// @todo check for better way to pass these structs
	w_cdev = cdev;
	w_psock = psock;

	return result;
}

static void disable_psock(struct f_psock *psock )
{
	if(psock)
	{
		usb_ep_disable(psock->bulk_in_ep);
		usb_ep_disable(psock->bulk_out_ep);
		usb_ep_disable(psock->cmd_in_ep);
		usb_ep_disable(psock->cmd_out_ep);
	}
}



/**
 * Sets the interface alt setting
 * As we have no alt settings yet value will be zero.
 * But interface should be disabled / enabled again
 */
static int psock_set_alt( struct usb_function *f , unsigned intf, unsigned alt )
{
	int ret;

	struct f_psock	*psock = func_to_psock(f);
	struct usb_composite_dev *cdev = f->config->cdev;

	disable_psock(psock);
	ret = enable_psock(cdev, psock );
	return ret;
}

static void psock_disable(struct usb_function *f )
{
	struct f_psock	*sock = func_to_psock(f);

	disable_psock(sock);
}


static struct usb_function *psock_alloc(struct usb_function_instance *fi)
{
	struct f_psock_opts *psock_opts;
	struct f_psock *psock;

	psock = kzalloc( (sizeof *psock ), GFP_KERNEL );
	if ( !psock )
	{
		return ERR_PTR(-ENOMEM);
	}

	psock_opts = container_of(fi, struct f_psock_opts, func_inst );

	mutex_lock(&psock_opts->lock );
	psock_opts->refcnt++;
	mutex_unlock(&psock_opts->lock);

        psock->function.name = "psock";
        psock->function.bind = psock_bind;
        psock->function.set_alt = psock_set_alt;
        psock->function.disable = psock_disable;
        psock->function.strings = psock_strings;

        psock->function.free_func = psock_free_func;
	printk(KERN_INFO "psock_alloc exit");

        return &psock->function;

}

/**
 *
 * usb instance allocation handling
 */

static inline struct f_psock_opts *to_f_psock_opts(struct config_item *item)
{
        return container_of(to_config_group(item), struct f_psock_opts,
                            func_inst.group);
}

static void psock_attr_release(struct config_item *item)
{
        struct f_psock_opts *psock_opts = to_f_psock_opts(item);
        usb_put_function_instance(&psock_opts->func_inst);
}

static struct configfs_item_operations psock_item_ops = {
        .release                = psock_attr_release,
};


static struct configfs_attribute *psock_attrs[] = {
        NULL,
};


static struct config_item_type psock_func_type = {
	        .ct_item_ops    = &psock_item_ops,
		.ct_attrs       = psock_attrs,
		.ct_owner       = THIS_MODULE,
};


static void psock_free_instance(struct usb_function_instance *fi)
{
        struct f_psock_opts *psock_opts;

        psock_opts = container_of(fi, struct f_psock_opts, func_inst);
        kfree(psock_opts);
}


static struct usb_function_instance *psock_alloc_inst(void)
{
	struct f_psock_opts *psock_opts;

	psock_opts = kzalloc( sizeof(*psock_opts ) , GFP_KERNEL );
	if ( !psock_opts )
	{
		return ERR_PTR(-ENOMEM);
	}

	mutex_init(&psock_opts->lock);

	psock_opts->func_inst.free_func_inst = psock_free_instance;

	config_group_init_type_name( &psock_opts->func_inst.group, "", &psock_func_type);

	return &psock_opts->func_inst;
}


DECLARE_USB_FUNCTION(psock, psock_alloc_inst, psock_alloc);

int f_psock_init_gadget( void )
{
	usb_function_register( &psockusb_func );

	return 0;
}


int f_psock_cleanup_gadget( void )
{
	usb_function_unregister( &psockusb_func);
	return 0;
}
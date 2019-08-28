/**
 * @file f_psock_gadget.c
 * @brief Usb gadget / composite framework integration for the f_psock kernel module
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/device.h>

#include <linux/usb/composite.h>

#include "psock_proxy_msg.h"
#include "f_psock_proxy.h"
#include "scm.h"

#define PSOCK_PROXY_JIFFIES 50
#define PSOCK_GADGET_MAX_SEND 5
#define PSOCK_GADGET_BUF_SIZE 512

extern void f_psock_proxy_sched_process_in_msg(void);

/**************************************************************************
 *  f_psock structure definitions
 **************************************************************************/

/**
 * Usb function instance structure definition
 */
struct f_psock_opts {
	struct usb_function_instance func_inst;

	unsigned bulk_buflen;
	unsigned qlen;

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

        unsigned                qlen;
        unsigned                buflen;
};

/**
 * Forward declarations
 */
static int alloc_msg_send_request( struct usb_composite_dev *cdev, struct f_psock *psock, void* msg, size_t len );
static int alloc_msg_read_request( struct usb_composite_dev *cdev, struct f_psock *psock );
static int msg_read_cmd( struct f_psock *psock );
static int alloc_msg_send_cmd( struct f_psock *psock );

/**************************************************************************
 * Workqueue and related
 **************************************************************************/
static struct workqueue_struct *f_psock_gadget_work_queue = NULL;
static struct delayed_work f_psock_gadget_work = {0};

static struct workqueue_struct *f_psock_gadget_read_work_queue = NULL;
static struct delayed_work f_psock_gadget_read_work = {0};

static struct workqueue_struct *f_psock_gadget_cmd_read_queue = NULL;
static struct delayed_work f_psock_gadget_cmd_read = {0};

static struct workqueue_struct *f_psock_gadget_cmd_write_queue = NULL;
static struct delayed_work f_psock_gadget_cmd_write = {0};

// @todo check for better way to keep this info as this makes it impossible to use more then one instnace
static struct usb_composite_dev *w_cdev;
static struct f_psock *w_psock; 

uint8_t *FIXED_MSG;
size_t FIXED_MSG_LEN;
void * RECV_BUFFER;
size_t RECV_BUFFER_LEN;
void * CMD_RECV_BUFFER;
size_t CMD_RECV_BUFFER_LEN;

/* Continually send and recieve on all endpoints */

void f_psock_gadget_work_handler( struct work_struct *work )
{
	alloc_msg_send_request( w_cdev, w_psock, (void*)FIXED_MSG, FIXED_MSG_LEN);

	//Do this again in 15s
	printk("Queuing work again");
	queue_delayed_work( f_psock_gadget_work_queue, &f_psock_gadget_work, 1500 );
}

void f_psock_gadget_read_handler( struct work_struct *work )
{
	alloc_msg_read_request(w_cdev, w_psock);
}


void f_psock_gadget_cmd_write_handler( struct work_struct *work )
{
	alloc_msg_send_cmd( w_psock );

	//Do this again in 15s
	printk("Queuing work again");
	queue_delayed_work( f_psock_gadget_cmd_write_queue, &f_psock_gadget_cmd_write, 1500 );
}
void f_psock_gadget_cmd_read_handler( struct work_struct *work )
{
	msg_read_cmd(w_psock);
}


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
	.wMaxPacketSize  = cpu_to_le16(MAX_CTRL_PACKET_SIZE),
	.bInterval	 = 32,
};

static struct usb_endpoint_descriptor
f_psock_fs_ctrl_source_desc  = {
	.bLength         = USB_DT_ENDPOINT_SIZE,
	.bDescriptorType = USB_DT_ENDPOINT,

	.bEndpointAddress = USB_DIR_IN,
	.bmAttributes    = USB_ENDPOINT_XFER_INT,
	.wMaxPacketSize  = cpu_to_le16(MAX_CTRL_PACKET_SIZE),
	.bInterval 	 = 32,
};

static struct usb_endpoint_descriptor
f_psock_hs_ctrl_sink_desc = {
	.bLength         = USB_DT_ENDPOINT_SIZE,
	.bDescriptorType = USB_DT_ENDPOINT,

	.bEndpointAddress = USB_DIR_OUT,
	.bmAttributes    = USB_ENDPOINT_XFER_INT,
	.wMaxPacketSize  = cpu_to_le16(MAX_CTRL_PACKET_SIZE),
	.bInterval	 = USB_MS_TO_HS_INTERVAL(32),
};
static struct usb_endpoint_descriptor
f_psock_hs_ctrl_source_desc = {
	.bLength         = USB_DT_ENDPOINT_SIZE,
	.bDescriptorType = USB_DT_ENDPOINT,

	.bEndpointAddress = USB_DIR_IN,
	.bmAttributes    = USB_ENDPOINT_XFER_INT,
	.wMaxPacketSize  = cpu_to_le16(MAX_CTRL_PACKET_SIZE),
	.bInterval 	 = USB_MS_TO_HS_INTERVAL(32),
};


static struct usb_endpoint_descriptor
f_psock_ss_ctrl_sink_desc = {
	.bLength         = USB_DT_ENDPOINT_SIZE,
	.bDescriptorType = USB_DT_ENDPOINT,

	.bEndpointAddress = USB_DIR_OUT,
	.bmAttributes    = USB_ENDPOINT_XFER_INT,
	.wMaxPacketSize  = cpu_to_le16(MAX_CTRL_PACKET_SIZE),
	.bInterval	 = USB_MS_TO_HS_INTERVAL(32),
};
static struct usb_endpoint_descriptor
f_psock_ss_ctrl_source_desc = {
	.bLength         = USB_DT_ENDPOINT_SIZE,
	.bDescriptorType = USB_DT_ENDPOINT,

	.bEndpointAddress = USB_DIR_IN,
	.bmAttributes    = USB_ENDPOINT_XFER_INT,
	.wMaxPacketSize  = cpu_to_le16(MAX_CTRL_PACKET_SIZE),
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


/**********************************************************************
 *
 **********************************************************************/



void psock_debug_hex_dump (char *desc, void *addr, int len)
{
    int i;
    unsigned char buff[17];
    unsigned char *pc = (unsigned char*)addr;

    // Output description if given.
    if (desc != NULL)
        printk ("%s (%d byte read):\n", desc, len);

    if (len == 0)
    {
        printk("  ZERO LENGTH\n");
        return;
    }
    if (len < 0)
    {
        printk("  NEGATIVE LENGTH: %i\n",len);
        return;
    }

    // Process every byte in the data.
    for (i = 0; i < len; i++)
    {
        // Multiple of 16 means new line (with line offset).

        if ((i % 16) == 0)
        {
            // Just don't print ASCII for the zeroth line.
            if (i != 0)
                printk (KERN_CONT "  %s\n", buff);

            // Output the offset.
            printk (KERN_CONT "  %04x ", i);
        }

        // Now the hex code for the specific character.
        printk (KERN_CONT " %02x", pc[i]);

        // And store a printable ASCII character for later.
        if ((pc[i] < 0x20) || (pc[i] > 0x7e))
            buff[i % 16] = '.';
        else
            buff[i % 16] = pc[i];
        buff[(i % 16) + 1] = '\0';
    }

    // Pad out last line if not exactly 16 characters.
    while ((i % 16) != 0)
    {
        printk (KERN_CONT "   ");
        i++;
    }

    // And print the final ASCII bit.
    printk (KERN_CONT "  %s\n", buff);
}


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

	printk(KERN_INFO "psock_free_func enter");
	
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

	printk(KERN_INFO "enable_endpoint enter");

	result = config_ep_by_speed( cdev->gadget, &(psock->function), ep );

	result = usb_ep_enable(ep);

	ep->driver_data = psock;

	result = 0;

	return result;
}


static void psock_send_complete( struct usb_ep *ep, struct usb_request *req )
{
	printk(KERN_INFO "psock_send_complete with status=%d",req->status);
}

static void psock_send_cmd_complete( struct usb_ep *ep, struct usb_request *req )
{
	printk(KERN_INFO "psock_send_cmd_complete with status=%d",req->status);
}

/* Recieves an incoming message from the host and passes it to the proxy */
static void psock_read_complete( struct usb_ep *ep, struct usb_request *req )
{
	printk(KERN_INFO "psock_read_complete enter");
	if (req->status)
	{
		printk(KERN_ERR "psock_read_complete came back with status=%d",req->status);
	}
	else
	{
		printk(KERN_INFO "req->buf=%p actual=%d\n",req->buf,req->actual);
		psock_debug_hex_dump("USB read:", req->buf, req->length);
	}
	

	queue_delayed_work( f_psock_gadget_read_work_queue, &f_psock_gadget_read_work, 0 );
}

static void psock_cmd_read_complete( struct usb_ep *ep, struct usb_request *req)
{
	printk(KERN_INFO "psock_cmd_read_complete enter");
	if (req->status)
	{
		printk(KERN_ERR "psock_cmd_read_complete came back with status=%d",req->status);
	}
	else
	{
		printk(KERN_INFO "psock_cmd_read_complete req->buf=%p actual=%d\n",req->buf,req->actual);
		psock_debug_hex_dump("psock_cmd_read_complete USB read:", req->buf, req->length);
	}
}

static int alloc_msg_send_request( struct usb_composite_dev *cdev, struct f_psock *psock, void *msg, size_t len )
{
	printk(KERN_INFO "alloc_msg_send_request enter");
	struct usb_request *out_req;

	out_req = usb_ep_alloc_request( psock->bulk_in_ep, GFP_ATOMIC );
	out_req->buf = msg;
	out_req->length = len;

	// We put a pointer to the msg in the context
	out_req->context = msg;

	psock_debug_hex_dump("alloc_msg_send_request sending:", out_req->buf, len);

	out_req->complete = psock_send_complete;
	usb_ep_queue( psock->bulk_in_ep, out_req, GFP_ATOMIC );

	return 0;	
}


static int alloc_msg_read_request( struct usb_composite_dev *cdev, struct f_psock *psock )
{
	struct usb_request *out_req;

	printk(KERN_INFO "alloc_msg_read_request enter");

	out_req = usb_ep_alloc_request( psock->bulk_out_ep, GFP_ATOMIC );
	out_req->length = RECV_BUFFER_LEN;
	out_req->buf = RECV_BUFFER;
	out_req->dma = 0;
	out_req->complete = psock_read_complete;
	usb_ep_queue( psock->bulk_out_ep, out_req, GFP_ATOMIC );

	return 0;
}


static int msg_read_cmd( struct f_psock *psock )
{
	struct usb_request *out_req;
	int ret = 0;
	printk(KERN_INFO "msg_read_cmd enter");

	out_req = usb_ep_alloc_request( psock->cmd_out_ep, GFP_ATOMIC );
	out_req->length = CMD_RECV_BUFFER_LEN;
	out_req->buf = CMD_RECV_BUFFER;
	out_req->dma = 0;
	out_req->complete = psock_cmd_read_complete;
	usb_ep_queue( psock->cmd_out_ep, out_req, GFP_ATOMIC );

	printk(KERN_INFO "Exit msg_read_cmd");
	return ret;
}

static int alloc_msg_send_cmd( struct f_psock *psock )
{
	printk(KERN_INFO "alloc_msg_send_request enter");
	struct usb_request *out_req;

	out_req = usb_ep_alloc_request( psock->cmd_in_ep, GFP_ATOMIC );
	out_req->buf = kmalloc(sizeof(__le32),GFP_KERNEL);
	*((__le32*)out_req->buf) = cpu_to_le32(254);
	out_req->length = sizeof(__le32);

	// We put a pointer to the msg in the context
	out_req->context = NULL;

	psock_debug_hex_dump("alloc_msg_send_cmd sending:", out_req->buf, out_req->length);

	out_req->complete = psock_send_cmd_complete;
	usb_ep_queue( psock->cmd_in_ep, out_req, GFP_ATOMIC );

	return 0;	
}

/**
 * @todo add error out that disables endpoint when fail
 * @todo check if its better two use 2 functions for the complete part
 */
static int enable_psock( struct usb_composite_dev *cdev, struct f_psock *psock )
{
	int result = 0;
	uint16_t inc = 0;
    	int i;

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

	//DEV: Create the dummy send structs
	FIXED_MSG_LEN = 2048;
	FIXED_MSG = kmalloc(FIXED_MSG_LEN, GFP_KERNEL);
	//For easy viewing the data will be constant FFXXXXFF wher the Xs incriment and wrap
	for(i=0;i<FIXED_MSG_LEN;i+=4)
	{
		FIXED_MSG[i] = 0xFF;
		*((uint16_t*)(FIXED_MSG+i+1)) = inc;
		FIXED_MSG[i+3] = 0xFF;
		inc++;
	}

	RECV_BUFFER_LEN = 512; //Arbitrary value above 512
	CMD_RECV_BUFFER_LEN = 512; //Arbitrary value above 512
	RECV_BUFFER = kzalloc(RECV_BUFFER_LEN,GFP_ATOMIC);
	CMD_RECV_BUFFER = kzalloc(CMD_RECV_BUFFER_LEN,GFP_ATOMIC);

	queue_delayed_work( f_psock_gadget_work_queue, &f_psock_gadget_work, 1000 );
	queue_delayed_work( f_psock_gadget_read_work_queue, &f_psock_gadget_read_work, 0 );
	queue_delayed_work( f_psock_gadget_cmd_write_queue, &f_psock_gadget_cmd_write, 1500 );
	queue_delayed_work( f_psock_gadget_cmd_read_queue, &f_psock_gadget_cmd_read, 0 );

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

	printk(KERN_INFO "psock_set_alt enter");

	struct f_psock	*psock = func_to_psock(f);
	struct usb_composite_dev *cdev = f->config->cdev;

	disable_psock(psock);
	ret = enable_psock(cdev, psock );
	return ret;
}

static void psock_disable(struct usb_function *f )
{
	struct f_psock	*sock = func_to_psock(f);
	printk(KERN_INFO "psock_disable enter");

	disable_psock(sock);
}


static struct usb_function *psock_alloc(struct usb_function_instance *fi)
{
	struct f_psock_opts *psock_opts;
	struct f_psock *psock;

	printk(KERN_INFO "psock_alloc enter");
	psock = kzalloc( (sizeof *psock ), GFP_KERNEL );
	if ( !psock )
	{
		return ERR_PTR(-ENOMEM);
	}

	psock_opts = container_of(fi, struct f_psock_opts, func_inst );

	mutex_lock(&psock_opts->lock );
	psock_opts->refcnt++;
	mutex_unlock(&psock_opts->lock);

	psock->buflen = psock_opts->bulk_buflen;
	psock->qlen = psock_opts->qlen;

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



static ssize_t f_psock_opts_bulk_buflen_show(struct config_item *item, char *page)
{
        struct f_psock_opts *opts = to_f_psock_opts(item);
        int result;

        mutex_lock(&opts->lock);
        result = sprintf(page, "%d\n", opts->bulk_buflen);
        mutex_unlock(&opts->lock);

        return result;
}

static ssize_t f_psock_opts_bulk_buflen_store(struct config_item *item,
                                    const char *page, size_t len)
{
        struct f_psock_opts *opts = to_f_psock_opts(item);
        int ret;
        u32 num;

        mutex_lock(&opts->lock);
        if (opts->refcnt) {
                ret = -EBUSY;
                goto end;
        }

        ret = kstrtou32(page, 0, &num);
        if (ret)
                goto end;

        opts->bulk_buflen = num;
        ret = len;
end:
        mutex_unlock(&opts->lock);
        return ret;
}



CONFIGFS_ATTR(f_psock_opts_, bulk_buflen);

static ssize_t f_psock_opts_qlen_show(struct config_item *item, char *page)
{
        struct f_psock_opts *opts = to_f_psock_opts(item);
        int result;

        mutex_lock(&opts->lock);
        result = sprintf(page, "%d\n", opts->qlen);
        mutex_unlock(&opts->lock);

        return result;
}



static ssize_t f_psock_opts_qlen_store(struct config_item *item,
                                    const char *page, size_t len)
{
        struct f_psock_opts *opts = to_f_psock_opts(item);
        int ret;
        u32 num;

        mutex_lock(&opts->lock);
        if (opts->refcnt) {
                ret = -EBUSY;
                goto end;
        }

        ret = kstrtou32(page, 0, &num);
        if (ret)
                goto end;

        opts->qlen = num;
        ret = len;
end:
        mutex_unlock(&opts->lock);
        return ret;
}



CONFIGFS_ATTR(f_psock_opts_, qlen);

static void psock_attr_release(struct config_item *item)
{
        struct f_psock_opts *psock_opts = to_f_psock_opts(item);

        usb_put_function_instance(&psock_opts->func_inst);
}


static struct configfs_item_operations psock_item_ops = {
        .release                = psock_attr_release,
};


static struct configfs_attribute *psock_attrs[] = {
        &f_psock_opts_attr_qlen,
        &f_psock_opts_attr_bulk_buflen,
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
	psock_opts->bulk_buflen = PSOCK_GADGET_BUF_SIZE;
	psock_opts->qlen = 1; // At the moment we test with 1 queued transmission

	config_group_init_type_name( &psock_opts->func_inst.group, "", &psock_func_type);

	return &psock_opts->func_inst;
}


DECLARE_USB_FUNCTION(psock, psock_alloc_inst, psock_alloc);

int f_psock_init_gadget( void )
{
	printk(KERN_INFO "f_psock_init_gadget enter");

	usb_function_register( &psockusb_func );

	// Initialize the work structs
	INIT_DELAYED_WORK( &f_psock_gadget_work, f_psock_gadget_work_handler );
	INIT_DELAYED_WORK( &f_psock_gadget_read_work, f_psock_gadget_read_handler );
	INIT_DELAYED_WORK( &f_psock_gadget_cmd_write, f_psock_gadget_cmd_write_handler );
	INIT_DELAYED_WORK( &f_psock_gadget_cmd_read, f_psock_gadget_cmd_read_handler );

	f_psock_gadget_work_queue = create_workqueue( "f_psock_gadget_work_queue" );
	f_psock_gadget_read_work_queue = create_workqueue( "f_psock_gadget_read_work" );
	f_psock_gadget_cmd_write_queue = create_workqueue( "f_psock_gadget_cmd_write_queue");
	f_psock_gadget_cmd_read_queue = create_workqueue( "f_psock_gadget_cmd_read_queue");

	printk(KERN_INFO "f_psock_init_gadget exit");

	return 0;
}


int f_psock_cleanup_gadget( void )
{
	printk(KERN_INFO "f_psock_cleanup_gadget enter");
	usb_function_unregister( &psockusb_func);
	return 0;
}
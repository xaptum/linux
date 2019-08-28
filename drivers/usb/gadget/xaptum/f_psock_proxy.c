/**
 * @file f_psock_proxy.c 
 * @brief Implementation for the Proxying of the sockets
 */
#include <linux/circ_buf.h>
#include <linux/eventpoll.h>
#include <linux/printk.h>
#include <linux/net.h>
#include <linux/kernel.h>
#include <linux/poll.h>
#include <linux/spinlock.h>
#include <net/sock.h>

#define F_PSOCK_PROXY_JIFFIES 50
#define F_PSOCK_MSG_TIMEOUT 10000
#define F_PSOCK_MAX_MSG_WORK	5

#define XARPCD_SUCCESS 1
#define XARPCD_FAIL 0

// Note this should be a multiple of 2!!
// Is the amount of msg the buffer can hold
#define F_PSOCK_BUFF_SIZE 16

// Forward declarations
static int f_psock_proxy_push_out_msg( void *msg );
int f_psock_proxy_pop_in_msg( void ** msg );
int f_psock_proxy_wait_send( psock_proxy_msg_t *msg );

// Lets keep track of the number of sockets (Used for local socket_id )
static int sock_counter = 0;
// Lets also keep track of the msg, so we can have a unique id for all msgs
static int msg_counter = 0;

// List of msgs waiting for an answer
LIST_HEAD( wait_list );

//List of received messages waiting to be read
LIST_HEAD( async_list );

/* Define mutexes to protect the message queues */
DEFINE_MUTEX(f_psock_in_queue_mutex);
DEFINE_MUTEX(f_psock_out_queue_mutex);

spinlock_t f_psock_out_queue_sl;
spinlock_t f_psock_in_queue_sl;

/* A lookup table for sockets being polled */
struct sock **f_psock_lookup;
static const int PSOCK_LOOKUP_SIZE = 256;

/**
 * Function to find a msg on the wait list
 */
static psock_proxy_msg_t *wait_list_get_msg_id( int id )
{
	struct list_head *position = NULL;
	list_for_each( position, &wait_list )
	{
		psock_proxy_msg_t *msg = list_entry( position, psock_proxy_msg_t, list_handle );
		if ( msg->msg_id == id )
		{
			return msg;
		}
	}
	return NULL;
}

/**
 * Function to find a msg on the async list
 */
static psock_proxy_msg_t *async_list_get_socket_msg( int id )
{
	struct list_head *position = NULL;
	list_for_each( position, &async_list )
	{
		psock_proxy_msg_t *msg = list_entry( position, psock_proxy_msg_t, list_handle );
		if ( msg->sock_id == id )
		{
			return msg;
		}
	}
	return NULL;
}

/**
 * Wait queue where we park action msgs that are sent, until we have a reply
 * msg->state == MSG_ANSWERED
 * or until msg sent if we dont care about the reply
 */
static wait_queue_head_t f_psock_proxy_wait_queue;

// Worker that periodically checks the wait queue
static struct workqueue_struct *f_psock_proxy_work_queue;
static struct delayed_work f_psock_work; 

void f_psock_proxy_handle_in_msg( struct psock_proxy_msg *msg )
{
	struct psock_proxy_msg *orig;
	struct sock *sk;

	/* If the message is from async from a polling socket */
	if( msg->type == F_PSOCK_MSG_ASYNC )
	{
		/* Add the msg to the list of waiting for an answer msgs */
		INIT_LIST_HEAD( &msg->list_handle );
		list_add_tail( &msg->list_handle, &async_list );

		/* Wake up the socket */
		sk = f_psock_lookup[msg->sock_id % PSOCK_LOOKUP_SIZE];
		if(sk)
			sk->sk_data_ready(sk);
	}
	else if ( msg->type == F_PSOCK_MSG_ACTION_REPLY )
	{
		orig = wait_list_get_msg_id( msg->msg_id );
		if ( orig != NULL )
		{
			orig->related = msg;
			orig->state = MSG_ANSWERED;
		}
		else
		{
			printk( "f_psock_proxy: Could not find original msg_id :%d\n", msg->msg_id);
		}
	}

}

// Work queue function
void f_psock_work_handler( struct work_struct *work )
{
	struct psock_proxy_msg *msg;
	// Handle pending incoming msg's 
	while( (f_psock_proxy_pop_in_msg( (void **)&msg  ) == F_PSOCK_SUCCESS ) )
	{
		f_psock_proxy_handle_in_msg( msg );
	}
	
	// Wake up the msgs that got an answer
	wake_up( &f_psock_proxy_wait_queue );
}

/**
 * Use this buffer to buffer incoming msgs from the usb stack
 */
static struct circ_buf *in_buffer;

/**
 * Use this buffer to send msgs to the usb stack
 */
static struct circ_buf *out_buffer;

/**
 * Item for in the circular buffers
 */
struct psock_buf_item
{
	void *msg;
};

/**
 * Function creates the in_buffer
 */
static int f_psock_proxy_create_in_buffer( void )
{
	// Create the in_buffer
	in_buffer = kzalloc( sizeof(struct circ_buf), GFP_KERNEL );
	if ( in_buffer == NULL )
	{
		printk("Error allocating circ in_buffer\n" );
	}
	in_buffer->head = 0;
	in_buffer->tail = 0;

	in_buffer->buf = (char * ) kzalloc( F_PSOCK_BUFF_SIZE* sizeof(struct psock_buf_item ) , GFP_KERNEL);

	if ( in_buffer->buf == NULL )
	{
		printk("Error allcating buff in in_buffer\n" );
	}

	return F_PSOCK_SUCCESS;


}

/**
 * Functio creates the out_buffer
 */
static int f_psock_proxy_create_out_buffer( void )
{

	// Create the out_buffer
	out_buffer = kzalloc( sizeof(struct circ_buf), GFP_KERNEL );
	if ( out_buffer == NULL )
	{
		printk("Error allocating circ out_buffer\n" );
	}	
	out_buffer->head = 0;
	out_buffer->tail = 0;

	out_buffer->buf = (char *) kzalloc( F_PSOCK_BUFF_SIZE* sizeof(struct psock_buf_item) , GFP_KERNEL );

	if ( out_buffer->buf == NULL )
	{
		printk("Error allocating buff in out_buffer\n" );
	}

	return F_PSOCK_SUCCESS;
}


/**
 * Initialize the proxy
 */
int f_psock_proxy_init( void )
{
	// Waitqueue initialization
	init_waitqueue_head( & f_psock_proxy_wait_queue );

 	// Initialize the buffers
	f_psock_proxy_create_in_buffer();
	f_psock_proxy_create_out_buffer();

	spin_lock_init(&f_psock_out_queue_sl);
	spin_lock_init(&f_psock_in_queue_sl);

	// Work and workqueue initialization
	f_psock_proxy_work_queue = create_workqueue( "f_psock_proxy_work_queue" );
	INIT_DELAYED_WORK( &f_psock_work, f_psock_work_handler );


	f_psock_lookup = kzalloc(sizeof(struct sock *) * PSOCK_LOOKUP_SIZE, GFP_KERNEL);

	return F_PSOCK_SUCCESS;
}



/** 
 * Cleanup the proxy
 */
int f_psock_proxy_cleanup( void )
{
	//@todo we should pop our message first so we can  the msgs also
	
	kfree( in_buffer->buf );
	kfree( out_buffer->buf );
	kfree( in_buffer );
	kfree( out_buffer );
	kfree(f_psock_lookup);

	destroy_workqueue( f_psock_proxy_work_queue );
	// @todo destroy the waitqueue

	return F_PSOCK_SUCCESS;
}

/***************************************************************
 * Socket side api
 **************************************************************/
/**
 * Here we create a create socket msg and put in on the queue to be sent over usb.
 */
int f_psock_proxy_create_socket( f_psock_proxy_socket_t *psk )
{
	psock_proxy_msg_t * msg = kzalloc( sizeof( psock_proxy_msg_t ) , GFP_KERNEL);
	if ( !msg )
	{
		printk( KERN_ERR "psock_proxy: Error allocating memory for create msg\n" );
		return F_PSOCK_FAIL; 
	}

	msg->magic = PSOCK_MSG_MAGIC;	
	msg->type = F_PSOCK_MSG_ACTION_REQUEST;
	msg->action = F_PSOCK_CREATE,
	msg->msg_id = msg_counter++;
	msg->sock_id = sock_counter++;
	msg->length = sizeof(struct psock_proxy_msg );
	msg->data = NULL;

	msg->state = MSG_PENDING; 
	msg->related = NULL;

	psk->local_id = msg->sock_id;
	psk->is_poll = 0;
	psk->can_write = 0;

	// Free the msg
	kfree( msg );

	return psk->local_id;
}

/**
 * Delete / close a socket and send close msg to the host
 */
int f_psock_proxy_delete_socket( f_psock_proxy_socket_t *psk )
{

        psock_proxy_msg_t * msg = kzalloc( sizeof( psock_proxy_msg_t ) , GFP_KERNEL);

	f_psock_lookup[psk->local_id % PSOCK_LOOKUP_SIZE] = NULL;
       
       	msg->magic = PSOCK_MSG_MAGIC;	
	msg->type = F_PSOCK_MSG_ACTION_REQUEST;
        msg->action = F_PSOCK_CLOSE;
	msg->msg_id = msg_counter++;
        msg->sock_id = psk->local_id;
        msg->length = sizeof( struct psock_proxy_msg );
        msg->data = NULL;

	msg->state = MSG_PENDING;
	msg->related = NULL;

	kfree( msg );

	return 0;
}

/**
 * Function waits until we have an incomming answer msg
 */
int f_psock_proxy_wait_answer( psock_proxy_msg_t *msg, psock_proxy_msg_t  **answermsg, int timeoutMS )
{
	int res = -1;

	// Add the msg to the list of waiting for an answer msgs
	INIT_LIST_HEAD( &msg->list_handle );
	list_add( &msg->list_handle, &wait_list );	

	wait_event_timeout( f_psock_proxy_wait_queue, ( msg->state == MSG_ANSWERED ), timeoutMS );

	if ( msg->state == MSG_ANSWERED )
	{
		// Handle the result
		*answermsg = msg->related;
		res = 1;
	}
	else 
	{
		printk( KERN_ERR "psock_proxy: Got a timeout waiting for msg answer on %d\n", msg->msg_id  );
	}

	// We can remove the item from the list now
	list_del( &msg->list_handle );

	return res;
}

/**
 * Function wait until a msg has been sent
 */
int f_psock_proxy_wait_send( psock_proxy_msg_t *msg )
{
        int res = F_PSOCK_FAIL;

        // Add the msg to the list of waiting for an answer msgs
        INIT_LIST_HEAD( &msg->list_handle );
        list_add( &msg->list_handle, &wait_list );

        wait_event_timeout( f_psock_proxy_wait_queue, ( msg->state == MSG_SEND ), F_PSOCK_MSG_TIMEOUT );
        if ( msg->state == MSG_SEND )
        {
                res = F_PSOCK_SUCCESS;
        }
        else
        {
                printk( KERN_ERR "Wait send timeout, should not happen\n" );
        }

        // We can remove the item from the list now
        list_del( &msg->list_handle );

        return res;

}

/**
 * Connect the socket to a remote address
 */
int f_psock_proxy_connect_socket( f_psock_proxy_socket_t *psk, struct sockaddr *addr, int alen )
{
	int result = F_PSOCK_FAIL;
	psock_proxy_msg_t * msg = kzalloc( sizeof( psock_proxy_msg_t ) , GFP_KERNEL);
	psock_proxy_msg_t * answer;
       
        msg->magic = PSOCK_MSG_MAGIC;	
	msg->type = F_PSOCK_MSG_ACTION_REQUEST;
        msg->action = F_PSOCK_CONNECT,
	msg->msg_id = msg_counter++;
        msg->sock_id = psk->local_id;
        msg->length = alen + sizeof( psock_proxy_msg_t );
        msg->data = kzalloc( alen, GFP_KERNEL );
	memcpy( msg->data, addr, alen );
	
	msg->state = MSG_PENDING;
	msg->related = NULL;

	kfree( msg );

	psk->can_write = 1;

	return result;
}

/**
 * Write data to the socket, will send a msg to the host with the data in it, so it can be written to the socket there
 * As long as the proxy out buffer is not full we assume we can write
 * @todo do length check (dont want it to be too big )
 * @todo check full buffer
 */
int f_psock_proxy_write_socket( f_psock_proxy_socket_t *fpsk, void *data, size_t len )
{
	int result = F_PSOCK_FAIL;
	struct sock *sk ;

	psock_proxy_msg_t * msg = kzalloc( sizeof( psock_proxy_msg_t ) , GFP_KERNEL);
 	psock_proxy_msg_t * answer;
	msg->magic = PSOCK_MSG_MAGIC;
        msg->type = F_PSOCK_MSG_ACTION_REQUEST;
        msg->action = F_PSOCK_WRITE;
	msg->msg_id = msg_counter++;
        msg->sock_id = fpsk->local_id;
        msg->length = len + sizeof( psock_proxy_msg_t );
        msg->data = data;

	msg->state = MSG_PENDING;
	msg->related = NULL;

	fpsk->can_write = 0;

	kfree( msg );
        return result;

}

int f_psock_proxy_poll_start(int local_id, struct sock *sk)
{
	int result = 0;
	psock_proxy_msg_t * answer;
	psock_proxy_msg_t * msg;

	/* Make sure we don't have a conflict */
	if(f_psock_lookup[local_id % PSOCK_LOOKUP_SIZE])
		printk(KERN_ERR "Conflicting polling socket local_id=%d.", local_id);

	msg = kzalloc( sizeof( psock_proxy_msg_t ) , GFP_KERNEL);
	msg->magic = PSOCK_MSG_MAGIC;
	msg->type = F_PSOCK_MSG_ACTION_REQUEST;
	msg->action = F_PSOCK_POLL,
	msg->msg_id = msg_counter++;
	msg->sock_id = local_id;
	msg->length = sizeof( psock_proxy_msg_t );
	msg->data = NULL;

	msg->state = MSG_PENDING;
	msg->related = NULL;


	kfree( msg );

	return result;
}

/**
 * Checks if there is an async message waiting for a socket
 * @param fpsk the proxy socket to check
 * @returns 1 if there is at least one message waiting, 0 otherwise.
 */
int f_psock_proxy_is_msg( int local_id )
{
	return async_list_get_socket_msg(local_id) ? 1 : 0;
}

/**
 * Read incoming data, if no data available yet, just returns
 * @todo check if we want to support blocking
 */
int f_psock_proxy_read_socket( f_psock_proxy_socket_t *psk, void *data, size_t len )
{
	int result = F_PSOCK_FAIL;
	psock_proxy_msg_t * msg;
	psock_proxy_msg_t * answer;

	/* If we are polling try to find a async message */
	if(psk->is_poll && (msg = async_list_get_socket_msg(psk->local_id)))
	{
		int payload_size = msg->status;
		int unread_size =  payload_size - msg->bytes_read;


		//Copy the memory to the data buffer
		result = min(unread_size,len);
		memcpy(data, (uint8_t*)msg->data+msg->bytes_read, result);

		/* If we read the entire packet delete it */
		if( (msg->bytes_read += result) == payload_size)
		{
			list_del(&msg->list_handle);
			kfree( msg->data );
			kfree( msg );
		}
	}
	/* If we are not polling make a regular blocking call */
	else if(!psk->is_poll)
	{
		msg =  kzalloc( sizeof( psock_proxy_msg_t ) , GFP_KERNEL);
		msg->magic = PSOCK_MSG_MAGIC;
		msg->type = F_PSOCK_MSG_ACTION_REQUEST;
		msg->action = F_PSOCK_READ;
		msg->msg_id = msg_counter++;
		msg->sock_id = psk->local_id;
		msg->length = sizeof( psock_proxy_msg_t );
		msg->data = NULL;
		msg->status = len;
		msg->state = MSG_PENDING;
		msg->related = NULL;

		kfree( msg ); 
 	}
	return result;
}

/**
 * Functions pushes a msg on the out buffer
 */
static int f_psock_proxy_push_out_msg( void *msg )
{
	return 0;
}

/**
 * Function to pop a msg from the in buffer
 */
int f_psock_proxy_pop_in_msg( void ** msg )
{
	struct psock_buf_item *item;
	unsigned long head;
	unsigned long tail;
	int ret = XARPCD_FAIL;

	spin_lock(&f_psock_in_queue_sl);

	head = in_buffer->head;
	tail = in_buffer->tail;
	
	if ( CIRC_CNT( head, tail, F_PSOCK_BUFF_SIZE*sizeof(struct psock_buf_item )) >= sizeof(struct psock_buf_item ) )
	{
		item = (struct psock_buf_item *)(&in_buffer->buf[tail]);
		
		*msg = item->msg;

		in_buffer->tail = (tail + sizeof( struct psock_buf_item )) & ( F_PSOCK_BUFF_SIZE * sizeof(struct psock_buf_item ) - 1 ); 
	
		ret = F_PSOCK_SUCCESS;
	}

	spin_unlock(&f_psock_in_queue_sl);

	return ret;
}


/**************************************************************
 * Usb communication side api
 *************************************************************/

/**
 * Function to pop a msg from the out buffer
 */
int f_psock_proxy_pop_out_msg( void ** msg )
{
	struct psock_buf_item *item;
	unsigned long head;
	unsigned long tail;
	int ret;

	ret = XARPCD_FAIL;

	spin_lock(&f_psock_out_queue_sl);
	head = out_buffer->head;
	tail = out_buffer->tail;

	 if ( CIRC_CNT( head, tail, F_PSOCK_BUFF_SIZE*sizeof(struct psock_buf_item )) >= sizeof(struct psock_buf_item ) )
	{
		item = (struct psock_buf_item *)(&out_buffer->buf[tail]);

		*msg = item->msg;

		out_buffer->tail = (tail + sizeof( struct psock_buf_item )) & ( F_PSOCK_BUFF_SIZE * sizeof(struct psock_buf_item ) - 1 );


		ret = F_PSOCK_SUCCESS;
	}

	spin_unlock(&f_psock_out_queue_sl);

	return ret;
}

/**
 * Function to push a msg to the in buffer
 */
int f_psock_proxy_push_in_msg( void * msg)
{
	struct psock_buf_item *item;

	unsigned long head;
	unsigned long tail;
	int ret = XARPCD_FAIL;

	spin_lock(&f_psock_in_queue_sl);

	head = in_buffer->head;
	tail = in_buffer->tail;

	if ( CIRC_SPACE( head, tail, F_PSOCK_BUFF_SIZE * sizeof(struct psock_buf_item )) >= sizeof(struct psock_buf_item ) ) 
	{
		item = ( struct psock_buf_item *)(&in_buffer->buf[head]);
		// Setup item
	
		item->msg = msg;
		// Update head
		in_buffer->head = (head + sizeof( struct psock_buf_item )) & ( F_PSOCK_BUFF_SIZE * sizeof(struct psock_buf_item ) - 1 );	
		
		return F_PSOCK_SUCCESS;
	}

	spin_unlock(&f_psock_in_queue_sl);

	return ret;
}

/* Schedules the in message workqueue function to run. */ 
void f_psock_proxy_sched_process_in_msg(void)
{
	queue_delayed_work( f_psock_proxy_work_queue, &f_psock_work, 0 );
}
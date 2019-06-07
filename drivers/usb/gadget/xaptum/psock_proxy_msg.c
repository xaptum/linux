#include <linux/kernel.h>
#include "psock_proxy_msg.h"

void psock_proxy_msg_to_packet(psock_proxy_msg_t *msg, psock_proxy_msg_packet_t *packet)
{
    packet->magic = cpu_to_le32(msg->magic);
    packet->type = cpu_to_le32(msg->type);
    packet->action = cpu_to_le32(msg->action);
    packet->msg_id = cpu_to_le32(msg->msg_id);
    packet->sock_id = cpu_to_le32(msg->sock_id);
    packet->status = cpu_to_le32(msg->status);
    packet->length = cpu_to_le32(msg->length - sizeof(psock_proxy_msg_t) + sizeof(psock_proxy_msg_packet_t));
    packet->state = cpu_to_le32(msg->state);
}

void psock_proxy_packet_to_msg(psock_proxy_msg_packet_t *packet, psock_proxy_msg_t *msg)
{
    msg->magic = le32_to_cpu(packet->magic);
    msg->type = le32_to_cpu(packet->type);
    msg->action = le32_to_cpu(packet->action);
    msg->msg_id = le32_to_cpu(packet->msg_id);
    msg->sock_id = le32_to_cpu(packet->sock_id);
    msg->status = le32_to_cpu(packet->status);
    msg->length = le32_to_cpu(packet->length) - sizeof(psock_proxy_msg_packet_t) + sizeof(psock_proxy_msg_t);
    msg->state = le32_to_cpu(packet->state);
    msg->data = NULL;
    msg->related = NULL;
    msg->wait_list = (const struct list_head){0};
}



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

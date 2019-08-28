#include <linux/types.h>
/* Constant definitions corresponding to the SCM standard */

#define MAX_CTRL_PACKET_SIZE 64

/* Op Codes */
typedef struct {
	uint8_t  opcode;
	uint8_t isFixedPayload : 1; /* Whether to pay attention to size */
	uint8_t isCommand : 1; /* Whether cmdLen or transLen contains the size */
	uint8_t : 0; /* Boundary */
	union {uint8_t cmdLen; uint16_t transLen;} size;
} scm_command_info;

const scm_command_info scm_cmd_open = {
	.opcode=0x00,
	.isFixedPayload=1,
	.isCommand=1,
	.size = {.cmdLen=0x08}};
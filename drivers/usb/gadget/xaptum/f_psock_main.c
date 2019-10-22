/**
 * @file f_psock_main.c
 * @brief Entry for the SCM driver
 * @author Daniel Berliner
 */

/**
 * @note At the moment for testing we directly load the module, 
 *       but this should be replace with the composite module laoding functions
 */

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/printk.h>

#include "f_psock_gadget.h"


MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Daniel Berliner");
MODULE_DESCRIPTION("Xaptum SCM Driver");
MODULE_VERSION("0.0.1");


static int __init f_psock_init(void)
{
	f_psock_init_gadget();
	return 0;
}

static void __exit f_psock_exit(void)
{
	f_psock_cleanup_gadget();
}


module_init( f_psock_init );
module_exit( f_psock_exit );
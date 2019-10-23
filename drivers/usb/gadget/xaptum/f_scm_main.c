/**
 * @file f_scm_main.c
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

#include "f_scm_gadget.h"


MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Daniel Berliner");
MODULE_DESCRIPTION("Xaptum SCM Driver");
MODULE_VERSION("0.0.1");


static int __init f_scm_init(void)
{
	f_scm_init_gadget();
	return 0;
}

static void __exit f_scm_exit(void)
{
	f_scm_cleanup_gadget();
}


module_init( f_scm_init );
module_exit( f_scm_exit );
/**
 * @file u_scm.h
 */
#ifndef _F_SCM_GADGET_H_
#define _F_SCM_GADGET_H_

struct f_scm_opts {
	struct usb_function_instance func_inst;
	struct mutex lock;
	int refcnt; 
};

#endif 
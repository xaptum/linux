/**
 * @file u_scm.h
 */
#ifndef _U_SCM_H_
#define _U_SCM_H_

struct f_scm_opts {
	struct usb_function_instance func_inst;
	struct mutex lock;
	int refcnt; 
};

#endif 

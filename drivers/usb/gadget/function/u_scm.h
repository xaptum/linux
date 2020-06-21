/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * u_scm.h -- USB Socket Control Module (SCM) function driver
 *
 * Copyright (C) 2018-2019 Xaptum, Inc.
 */
#ifndef _U_SCM_H_
#define _U_SCM_H_

struct f_scm_opts {
	struct usb_function_instance func_inst;
	struct mutex lock;
	int refcnt;
};

#endif

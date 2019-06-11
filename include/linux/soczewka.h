/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __LINUX_SOCZEWKA_H__
#define __LINUX_SOCZEWKA_H__

#include <linux/types.h>

void soczewka_scan_mem(const void *from, unsigned long n);
// TODO
int should_not_scan(void); 

#endif		/* __LINUX_SOCZEWKA_H__ */

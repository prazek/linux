/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __LINUX_SOCZEWKA_H__
#define __LINUX_SOCZEWKA_H__

#include <linux/types.h>

#define SOCZEWKA_MAX_NUM_DANGEROUS_WORDS  64
#define SOCZEWKA_MAX_LEN_DANGEROUS_WORD	 64

void soczewka_scan_mem(const void *from, unsigned long n);

#endif		/* __LINUX_SOCZEWKA_H__ */

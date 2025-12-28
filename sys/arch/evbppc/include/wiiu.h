/* $NetBSD$ */

/*-
 * Copyright (c) 2025 Jared McNeill <jmcneill@invisible.ca>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/*
 * Nintendo Wii U platform definitions.
 */

#ifndef _WIIU_H
#define _WIIU_H

#include <machine/wii.h>

#define WIIU_MEM1_BASE			0x00000000
#define WIIU_MEM1_SIZE			0x02000000	/* 32 MB */
#define WIIU_MEM0_BASE			0x08000000
#define WIIU_MEM0_SIZE			0x00300000	/* 3 MB */
#define WIIU_MEM2_BASE			0x10000000
#define WIIU_MEM2_SIZE			0x80000000	/* 2 GB */

#define WIIU_GFX_TV_BASE		0x17500000
#define WIIU_GFX_DRC_BASE		0x178c0000

#define WIIU_BUS_FREQ_HZ		248625000
#define WIIU_CPU_FREQ_HZ		(WIIU_BUS_FREQ_HZ * 5)
#define WIIU_TIMEBASE_FREQ_HZ		(WIIU_BUS_FREQ_HZ / 4)

#define WIIU_PI_BASE			0x0c000000

#define WIIU_DSP_BASE			0x0c280000

/* Processor interface registers */
#define WIIU_PI_INTSR0			(WIIU_PI_BASE + 0x78)
#define WIIU_PI_INTMSK0			(WIIU_PI_BASE + 0x7c)

/* Latte registers */
#define LT_PPCnINT1STS(n)		(HOLLYWOOD_PRIV_BASE + 0x440 + (n) * 0x10)
#define LT_PPCnINT2STS(n)		(HOLLYWOOD_PRIV_BASE + 0x444 + (n) * 0x10)
#define LT_PPCnINT1EN(n)		(HOLLYWOOD_PRIV_BASE + 0x448 + (n) * 0x10)
#define LT_PPCnINT2EN(n)		(HOLLYWOOD_PRIV_BASE + 0x44c + (n) * 0x10)
#define LT_IOPINT1STS			LT_PPCnINT1STS(3)
#define LT_IOPINT2STS			LT_PPCnINT2STS(3)
#define LT_IOPIRQINT1EN			LT_PPCnINT1EN(3)
#define LT_IOPIRQINT2EN			LT_PPCnINT2EN(3)
#define LT_CHIPREVID			(HOLLYWOOD_PRIV_BASE + 0x5a0)
#define  LT_CHIPREVID_MAGIC		__BITS(31, 16)
#define  LT_CHIPREVID_MAGIC_CAFE	0xCAFE
#define  LT_CHIPREVID_VERHI		__BITS(7, 4)
#define  LT_CHIPREVID_VERLO		__BITS(3, 0)
#define LT_PIMCOMPAT			(HOLLYWOOD_PRIV_BASE + 0x5b0)
#define  PPC_COMPAT			__BIT(5)

/* GPIOs */
#define WIIU_GPIO_POWER			0

/* Command line protocol */
#define WIIU_ARGV_MAGIC			0xCAFEFECA
struct wiiu_argv {
	uint32_t	magic;
	char		cmdline[256];
	void		*initrd;
	uint32_t	initrd_sz;
};
#define WIIU_ARGV_DATA			((volatile struct wiiu_argv *)0x89200000)

/* Declared in sys/arch/evbppc/wii/machdep.c */
extern bool wiiu_plat;
extern bool wiiu_native;

#endif /* !_WIIU_H */

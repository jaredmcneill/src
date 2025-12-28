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

#include <sys/cdefs.h>
__KERNEL_RCSID(0, "$NetBSD$");

#include <sys/param.h>
#include <sys/bus.h>
#include <sys/device.h>
#include <sys/systm.h>

#include <machine/wii.h>
#include <machine/wiiu.h>

#include <dev/wscons/wsconsio.h>
#include <dev/wscons/wsdisplayvar.h>
#include <dev/rasops/rasops.h>
#include <dev/wsfont/wsfont.h>
#include <dev/wscons/wsdisplay_vconsvar.h>
#include <dev/wsfb/genfbvar.h>

#include "mainbus.h"

/* Set to true to output to Gamepad instead of TV */
static bool	wiiufb_drc;

#define WIIUFB_BASE		(wiiufb_drc ? WIIU_GFX_DRC_BASE : \
					      WIIU_GFX_TV_BASE)
#define WIIUFB_WIDTH		(wiiufb_drc ? 854 : 1280)
#define WIIUFB_HEIGHT		(wiiufb_drc ? 480 : 720)
#define WIIUFB_BPP		32
#define WIIUFB_STRIDE		((wiiufb_drc ? 896 : 1280) * WIIUFB_BPP / NBBY)
#define WIIUFB_SIZE		(WIIUFB_STRIDE * WIIUFB_HEIGHT)

struct wiiufb_softc {
	struct genfb_softc	sc_gen;

	bus_space_tag_t		sc_bst;
	bus_space_handle_t	sc_bsh;
};

static int	wiiufb_match(device_t, cfdata_t, void *);
static void	wiiufb_attach(device_t, device_t, void *);

static bool	wiiufb_shutdown(device_t, int);
static int	wiiufb_ioctl(void *, void *, u_long, void *, int, lwp_t *);
static paddr_t	wiiufb_mmap(void *, void *, off_t, int);

void		wiiufb_consinit(void);

static struct genfb_ops wiiufb_ops = {
	.genfb_ioctl = wiiufb_ioctl,
	.genfb_mmap = wiiufb_mmap,
};

struct vcons_screen wiiufb_console_screen;
static struct wsscreen_descr wiiufb_stdscreen = {
	"std",
	0, 0,
	0,
	0, 0,
	0,
	NULL
};

CFATTACH_DECL_NEW(wiiufb, sizeof(struct wiiufb_softc),
	wiiufb_match, wiiufb_attach, NULL, NULL);

static int
wiiufb_match(device_t parent, cfdata_t cf, void *aux)
{
	struct mainbus_attach_args *maa = aux;

	return wiiu_native && strcmp(maa->maa_name, "genfb") == 0;
}

static void
wiiufb_attach(device_t parent, device_t self, void *aux)
{
	struct wiiufb_softc *sc = device_private(self);
	prop_dictionary_t dict = device_properties(self);
	struct mainbus_attach_args *maa = aux;
	void *bits;

	sc->sc_gen.sc_dev = self;
	sc->sc_bst = maa->maa_bst;

	/*
	 * powerpc bus_space_map will use the BAT mapping if present,
	 * ignoring the map flags passed in. Just use mapiodev directly
	 * to ensure that the FB is mapped by the kernel pmap.
	 */
	bits = mapiodev(WIIUFB_BASE, WIIUFB_SIZE, true);

	prop_dictionary_set_uint32(dict, "width", WIIUFB_WIDTH);
	prop_dictionary_set_uint32(dict, "height", WIIUFB_HEIGHT);
	prop_dictionary_set_uint8(dict, "depth", WIIUFB_BPP);
	prop_dictionary_set_uint16(dict, "linebytes", WIIUFB_STRIDE);
	prop_dictionary_set_uint32(dict, "address", WIIUFB_BASE);
	prop_dictionary_set_uint32(dict, "virtual_address", (uintptr_t)bits);
	prop_dictionary_set_bool(dict, "is_brg", true);

	genfb_init(&sc->sc_gen);

	aprint_naive("\n");
	aprint_normal(": Wii U %s framebuffer (%ux%u %u-bpp @ 0x%08x)\n",
	    wiiufb_drc ? "DRC" : "TV", WIIUFB_WIDTH, WIIUFB_HEIGHT,
	    WIIUFB_BPP, WIIUFB_BASE);

	pmf_device_register1(self, NULL, NULL, wiiufb_shutdown);

	genfb_cnattach();
	prop_dictionary_set_bool(dict, "is_console", true);
	genfb_attach(&sc->sc_gen, &wiiufb_ops);
}

static bool
wiiufb_shutdown(device_t self, int flags)
{
	genfb_enable_polling(self);
	return true;
}

static int
wiiufb_ioctl(void *v, void *vs, u_long cmd, void *data, int flag, lwp_t *l)
{
	struct wiiufb_softc *sc = v;
	struct wsdisplayio_bus_id *busid;
	struct wsdisplayio_fbinfo *fbi;
	struct rasops_info *ri;
	int error;

	switch (cmd) {
	case WSDISPLAYIO_GTYPE:
		*(u_int *)data = WSDISPLAY_TYPE_GENFB;
		return 0;
	case WSDISPLAYIO_GET_BUSID:
		busid = data;
		busid->bus_type = WSDISPLAYIO_BUS_SOC;
		return 0;
	case WSDISPLAYIO_GET_FBINFO:
		fbi = data;
		ri = &sc->sc_gen.vd.active->scr_ri;
		error = wsdisplayio_get_fbinfo(ri, fbi);
		if (error == 0) {
			fbi->fbi_flags |= WSFB_VRAM_IS_RAM;
		}
		return error;
	}

	return EPASSTHROUGH;
}

static paddr_t
wiiufb_mmap(void *v, void *vs, off_t off, int prot)
{
	struct wiiufb_softc *sc = v;

	if (off < 0 || off >= WIIUFB_SIZE) {
		return -1;
	}

	return bus_space_mmap(sc->sc_bst, WIIUFB_BASE, off, prot,
	    BUS_SPACE_MAP_LINEAR | BUS_DMA_PREFETCHABLE);
}

void
wiiufb_consinit(void)
{
	extern struct powerpc_bus_space wii_mem_tag;
	struct rasops_info *ri = &wiiufb_console_screen.scr_ri;
	long defattr;
	bus_space_handle_t bsh;
	void *bits;

	memset(&wiiufb_console_screen, 0, sizeof(wiiufb_console_screen));

	/* Must use the BAT mapping here as pmap isn't initialized yet. */
	bus_space_map(&wii_mem_tag, WIIUFB_BASE, WIIUFB_SIZE,
	    BUS_SPACE_MAP_LINEAR | BUS_SPACE_MAP_PREFETCHABLE, &bsh);
	bits = bus_space_vaddr(&wii_mem_tag, bsh);

	wsfont_init();

	ri->ri_width = WIIUFB_WIDTH;
	ri->ri_height = WIIUFB_HEIGHT;
	ri->ri_depth = WIIUFB_BPP;
	ri->ri_stride = WIIUFB_STRIDE;
	ri->ri_bits = bits;
	ri->ri_rnum = ri->ri_gnum = ri->ri_bnum = 8;
	ri->ri_bpos = 0;
	ri->ri_rpos = 8;
	ri->ri_gpos = 16;
	ri->ri_flg = RI_NO_AUTO | RI_CLEAR | RI_FULLCLEAR | RI_CENTER;
	rasops_init(ri, ri->ri_height / 8, ri->ri_width / 8);

	ri->ri_caps = WSSCREEN_WSCOLORS;
	rasops_reconfig(ri, ri->ri_height / ri->ri_font->fontheight,
	    ri->ri_width / ri->ri_font->fontwidth);

	wiiufb_stdscreen.nrows = ri->ri_rows;
	wiiufb_stdscreen.ncols = ri->ri_cols;
	wiiufb_stdscreen.textops = &ri->ri_ops;
	wiiufb_stdscreen.capabilities = ri->ri_caps;

	ri->ri_ops.allocattr(ri, 0, 0, 0, &defattr);

	wsdisplay_preattach(&wiiufb_stdscreen, ri, 0, 0, defattr);
}

/* $NetBSD$ */

/*-
 * Copyright (c) 2018 Jared McNeill <jmcneill@invisible.ca>
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
 * THIS SOFTWARE IS PROVIDED BY THE NETBSD FOUNDATION, INC. AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE FOUNDATION OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <sys/cdefs.h>

__KERNEL_RCSID(0, "$NetBSD$");

#include <sys/param.h>
#include <sys/bus.h>
#include <sys/device.h>
#include <sys/intr.h>
#include <sys/systm.h>
#include <sys/time.h>
#include <sys/kmem.h>

#include <dev/clk/clk_backend.h>

#include <dev/fdt/fdtvar.h>

static int rk_usb_match(device_t, cfdata_t, void *);
static void rk_usb_attach(device_t, device_t, void *);

#define	CON0_REG	0x00
#define	 CON0_SIDDQ	__BIT(13)

enum rk_usb_type {
	USB_RK3328 = 1,
};

static const struct of_compat_data compat_data[] = {
	{ "rockchip,rk3328-usb2phy",		USB_RK3328 },
	{ NULL }
};

struct rk_usb_clk {
	struct clk		base;
	bus_size_t		reg;
};

struct rk_usb_softc {
	device_t		sc_dev;
	bus_space_tag_t		sc_bst;
	bus_space_handle_t	sc_bsh;
	enum rk_usb_type	sc_type;

	struct clk_domain	sc_clkdom;
	struct rk_usb_clk	sc_usbclk;
};

#define USB_READ(sc, reg)			\
	bus_space_read_4((sc)->sc_bst, (sc)->sc_bsh, (reg))
#define USB_WRITE(sc, reg, val)			\
	bus_space_write_4((sc)->sc_bst, (sc)->sc_bsh, (reg), (val))

CFATTACH_DECL_NEW(rk_usb, sizeof(struct rk_usb_softc),
	rk_usb_match, rk_usb_attach, NULL, NULL);

static struct clk *
rk_usb_clk_get(void *priv, const char *name)
{
	struct rk_usb_softc * const sc = priv;

	if (strcmp(name, sc->sc_usbclk.base.name) != 0)
		return NULL;

	return &sc->sc_usbclk.base;
}

static void
rk_usb_clk_put(void *priv, struct clk *clk)
{
}

static u_int
rk_usb_clk_get_rate(void *priv, struct clk *clk)
{
	return 480000000;
}

static int
rk_usb_clk_enable(void *priv, struct clk *clk)
{
	struct rk_usb_softc * const sc = priv;

	USB_WRITE(sc, CON0_REG, USB_READ(sc, CON0_REG) | CON0_SIDDQ);

	return 0;
}

static int
rk_usb_clk_disable(void *priv, struct clk *clk)
{
	struct rk_usb_softc * const sc = priv;

	USB_WRITE(sc, CON0_REG, USB_READ(sc, CON0_REG) & ~CON0_SIDDQ);

	return 0;
}

static const struct clk_funcs rk_usb_clk_funcs = {
	.get = rk_usb_clk_get,
	.put = rk_usb_clk_put,
	.get_rate = rk_usb_clk_get_rate,
	.enable = rk_usb_clk_enable,
	.disable = rk_usb_clk_disable,
};

static struct clk *
rk_usb_fdt_decode(device_t dev, const void *data, size_t len)
{
	struct rk_usb_softc * const sc = device_private(dev);

	if (len != 0)
		return NULL;

	return &sc->sc_usbclk.base;
}

static const struct fdtbus_clock_controller_func rk_usb_fdt_funcs = {
	.decode = rk_usb_fdt_decode
};

static int
rk_usb_match(device_t parent, cfdata_t cf, void *aux)
{
	struct fdt_attach_args * const faa = aux;

	return of_match_compat_data(faa->faa_phandle, compat_data);
}

static void
rk_usb_attach(device_t parent, device_t self, void *aux)
{
	struct rk_usb_softc * const sc = device_private(self);
	struct fdt_attach_args * const faa = aux;
	const int phandle = faa->faa_phandle;
	bus_addr_t grf_addr, phy_addr, phy_size;

	sc->sc_dev = self;
	sc->sc_bst = faa->faa_bst;
	sc->sc_type = of_search_compatible(phandle, compat_data)->data;

	if (fdtbus_get_reg(OF_parent(phandle), 0, &grf_addr, NULL) != 0) {
		aprint_error(": couldn't get grf registers\n");
	}
	if (fdtbus_get_reg(phandle, 0, &phy_addr, &phy_size) != 0) {
		aprint_error(": couldn't get phy registers\n");
		return;
	}
	if (bus_space_map(sc->sc_bst, grf_addr + phy_addr, phy_size, 0, &sc->sc_bsh) != 0) {
		aprint_error(": couldn't map phy registers\n");
		return;
	}

	const char *clkname = fdtbus_get_string(phandle, "clock-output-names");
	if (clkname == NULL)
		clkname = faa->faa_name;

	sc->sc_clkdom.name = device_xname(self);
	sc->sc_clkdom.funcs = &rk_usb_clk_funcs;
	sc->sc_clkdom.priv = sc;
	sc->sc_usbclk.base.domain = &sc->sc_clkdom;
	sc->sc_usbclk.base.name = kmem_asprintf("%s", clkname);
	clk_attach(&sc->sc_usbclk.base);

	aprint_naive("\n");
	aprint_normal(": USB2PHY\n");

	fdtbus_register_clock_controller(self, phandle, &rk_usb_fdt_funcs);
}

# $NetBSD$
#
# Nintendo Wii U
#

include 	"arch/evbppc/conf/NINTENDO"

# SMP options
options 	MULTIPROCESSOR

# Enable Espresso specific workarounds
options 	PPC_IBMESPRESSO

# The workaround for Espresso's stwcx. errata is not compatible with
# PaX MPROTECT.
no options 	PAX_MPROTECT

# $NetBSD$

include 	"arch/nintendoppc/conf/GENERIC"

# SMP options
options 	MULTIPROCESSOR

# Enable Espresso specific workarounds
options 	PPC_IBMESPRESSO

# The workaround for Espresso's stwcx. errata is not compatible with
# PaX MPROTECT.
no options 	PAX_MPROTECT

# $NetBSD$

include 	"arch/nintendoppc/conf/GENERIC"

# SMP options
options 	MULTIPROCESSOR

# The workaround for Espresso's stwcx. errata is not compatible with
# PaX MPROTECT.
no options 	PAX_MPROTECT

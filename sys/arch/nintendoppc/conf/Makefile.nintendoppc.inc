#	$NetBSD$

RAMDISKDIR!=	cd ${NETBSDSRCDIR}/distrib/${THISPPC:T}/ramdisk && ${PRINTOBJDIR}

CFLAGS+=-mcpu=750
AFLAGS+=-mcpu=750

.ifndef TEXTADDR
BEGIN:
	echo "TEXTADDR not defined in kernel config!"
	exit 1
.endif

SYSTEM_FIRST_OBJ=	locore.o
SYSTEM_FIRST_SFILE=	${THISPPC}/nintendoppc/locore.S

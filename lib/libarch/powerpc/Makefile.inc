#	$NetBSD$

.include <bsd.own.mk>

.if (${MACHINE} == "nintendoppc")
SUBDIR=powerpc/espresso
.endif

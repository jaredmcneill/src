#	$NetBSD$

.include <bsd.own.mk>

.if (${MACHINE} == "evbppc")
SUBDIR=	powerpc/espresso
.endif

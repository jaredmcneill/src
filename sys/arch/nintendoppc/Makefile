#	$NetBSD$

.include <../powerpc/Makefile.inc>

TNINTENDOPPC=	${SYSDIR}/arch/nintendoppc/tags
SNINTENDOPPC=	${SYSDIR}/arch/nintendoppc/nintendoppc/*.[ch]
SNINTENDOPPC+=	${SYSDIR}/arch/nintendoppc/include/*.h
ANINTENDOPPC=	${SYSDIR}/arch/nintendoppc/nintendoppc/*.S

DNINTENDOPPC=	include

.include "../../kern/Make.tags.inc"

tags:
	-rm -f ${TNINTENDOPPC}
	-echo ${SNINTENDOPPC} ${SPPC} | xargs ctags -wadtf ${TNINTENDOPPC}
	-${FINDCOMM} | xargs ctags -wadtf ${TNINTENDOPPC}
	egrep "^ENTRY(.*)|^ALTENTRY(.*)" ${ANINTENDOPPC} ${APPC} | \
	    ${TOOL_SED} -e \
		"s;\([^:]*\):\([^(]*\)(\([^, )]*\)\(.*\);\3	\1	/^\2(\3\4$$/;" \
	    >> ${TNINTENDOPPC}
	sort -o ${TNINTENDOPPC} ${TNINTENDOPPC}

links:
	-for i in ${DNINTENDOPPC}; do \
	    cd $$i && rm -f tags; ln -s ../tags tags; done


SUBDIR=	compile include stand

.include <bsd.subdir.mk>

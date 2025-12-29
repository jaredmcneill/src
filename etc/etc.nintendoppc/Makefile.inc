#	$NetBSD$
#
#	etc.nintendoppc/Makefile.inc -- nintendoppc-specific etc Makefile targets
#

# If you change the list of distributed kernels, don't forget
# to update the release documentation in distrib/notes/common/contents

KERNEL_SETS+=		GENERIC
#KERNEL_SETS+=		GENERIC.MP
BUILD_KERNELS+=		INSTALL
#BUILD_KERNELS+=	INSTALL.MP

# Support for mkimage
MKIMAGE= 	${NETBSDSRCDIR}/distrib/utils/embedded/mkimage
IMAGE.rel=      ${RELEASEDIR}/${RELEASEMACHINEDIR}
IMAGE.dir=      ${IMAGE.rel}/binary/gzimg
IMAGE.kern=     ${IMAGE.rel}/binary/kernel
IMAGEENDIAN=	be

__mkimage: .USE
	TOOL_MAKE=${MAKE} \
	TOOL_MAKEFS=${TOOL_MAKEFS} \
	TOOL_DISKLABEL=${TOOL_DISKLABEL} \
	TOOL_FDISK=${TOOL_FDISK} \
	TOOL_GPT=${TOOL_GPT} \
	TOOL_GZIP=${TOOL_GZIP} \
	TOOL_MKNOD=${TOOL_MKNOD} \
	TOOL_PAX=${TOOL_PAX} \
	TOOL_MKUBOOTIMAGE=${TOOL_MKUBOOTIMAGE} \
	TOOL_MTREE=${TOOL_MTREE} \
	TOOL_SED=${TOOL_SED} \
	TOOL_PWD_MKDB=${TOOL_PWD_MKDB} \
	HOST_SH=${HOST_SH} \
	KERNOBJDIR=${KERNOBJDIR} \
	MACHINE=${MACHINE} \
	MKDTB=${MKDTB} \
	MKPOSTFIX=${MKPOSTFIX} \
	CKSUM=${CKSUM} \
	IMAGEDIR=${IMAGE.dir} \
	${HOST_SH} -x ${MKIMAGE} -h ${.TARGET:S/smp_//} -D ${DESTDIR} \
            -S ${NETBSDSRCDIR} -B ${IMAGEENDIAN} ${MKI_OPTS.${.TARGET}} \
            ${IMAGE.dir}/${.TARGET:S/smp_//}.img.gz

smp_nintendoppc: __mkimage
	cd ${KERNSRCDIR}/arch/nintendoppc/stand/wii && ${MAKE} release
MKI_OPTS.smp_nintendoppc=	-K ${IMAGE.kern} -x
SNAP_MD_POST_DEPS+=		smp_nintendoppc
INSTALLATION_DIRS+=		binary/gzimg
INSTALLATION_DIRS+=		installation/misc

snap_md_post: check_DESTDIR check_RELEASEDIR snap_post .WAIT ${SNAP_MD_POST_DEPS}

EXTRA_DIST	= nomacro.pl

bin_PROGRAMS	= minerb

minerb_SOURCES	= elist.h miner.h compat.h \
		  cpu-miner.c util.c \
		  sha2.c scrypt.c
if USE_ASM
if ARCH_x86
minerb_SOURCES += sha2-x86.S scrypt-x86.S
endif
if ARCH_x86_64
minerb_SOURCES += sha2-x64.S scrypt-x64.S
endif
if ARCH_ARM
minerb_SOURCES += sha2-arm.S scrypt-arm.S
endif
if ARCH_PPC
minerb_SOURCES += sha2-ppc.S scrypt-ppc.S
endif
endif
minerb_LDFLAGS	= $(PTHREAD_FLAGS)
minerb_LDADD	= @PTHREAD_LIBS@ @WS2_LIBS@
minerb_CFLAGS	= -fno-strict-aliasing
minerb_CPPFLAGS	= $(PTHREAD_FLAGS)


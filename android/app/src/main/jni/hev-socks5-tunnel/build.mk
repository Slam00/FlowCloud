# Build

rwildcard=$(foreach d,$(wildcard $1*), \
          $(call rwildcard,$d/,$2) \
          $(filter $(subst *,%,$2),$d))

SRCFILES=$(call rwildcard,$(SRCDIR)/,*.c *.S)

ifeq ($(REV_ID),)
  ifneq (,$(wildcard .rev-id))
    REV_ID=$(shell cat .rev-id)
  endif
  ifeq ($(REV_ID),)
    REV_ID=d9dca26
  endif
endif
VERSION_CFLAGS=-DCOMMIT_ID=\"$(REV_ID)\"

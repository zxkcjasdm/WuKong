# Copyright (C) 2023 Gramine contributors
# SPDX-License-Identifier: BSD-3-Clause

ARCH_LIBDIR ?= /lib/$(shell $(CC) -dumpmachine)

ifeq ($(DEBUG),1)
GRAMINE_LOG_LEVEL = debug
else
GRAMINE_LOG_LEVEL = error
endif

.PHONY: all
all: wkenclave.manifest
ifeq ($(SGX),1)
all: wkenclave.manifest.sgx wkenclave.sig
endif

# RA_TYPE ?= none
# RA_CLIENT_SPID ?=
# RA_CLIENT_LINKABLE ?= 0

wkenclave.manifest: wkenclave.manifest.template
	gramine-manifest \
		-Dlog_level=$(GRAMINE_LOG_LEVEL) \
		-Darch_libdir=$(ARCH_LIBDIR) \
		-Dentrypoint=$(realpath $(shell sh -c "command -v python3")) \
		$< > $@


# Make on Ubuntu <= 20.04 doesn't support "Rules with Grouped Targets" (`&:`),
# see the helloworld example for details on this workaround.
wkenclave.manifest.sgx wkenclave.sig: sgx_sign
	@:

.INTERMEDIATE: sgx_sign
sgx_sign: wkenclave.manifest
	gramine-sgx-sign \
		--manifest $< \
		--output $<.sgx



.PHONY: clean
clean:
	$(RM) *.manifest *.manifest.sgx *.token *.sig OUTPUT* *.PID TEST_STDOUT TEST_STDERR
	$(RM) -r scripts/__pycache__

.PHONY: distclean
distclean: clean
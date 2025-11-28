KMOD_CSDIO_VERSION = 1.0
KMOD_CSDIO_SITE = $(KMOD_CSDIO_PKGDIR)/src
KMOD_CSDIO_LICENSE = MIT
KMOD_CSDIO_DEPENDENCIES = linux
KMOD_CSDIO_SITE_METHOD = local

$(eval $(kernel-module))
$(eval $(generic-package))

define KMOD_CSDIO_GENERATE_HEADER
    echo "#define CONFIG_CSDIO_VENDOR_ID $(CSDIO_VID)" >  $(@D)/csdio_config.h
    echo "#define CONFIG_CSDIO_DEVICE_ID $(CSDIO_PID)" >> $(@D)/csdio_config.h
endef

KMOD_CSDIO_PRE_BUILD_HOOKS += KMOD_CSDIO_GENERATE_HEADER

#  Copyright (c) 2016 Afero, Inc. All rights reserved.

include $(TOPDIR)/rules.mk

PKG_NAME:=attrd
PKG_VERSION:=0.1
PKG_RELEASE:=1

USE_SOURCE_DIR:=$(CURDIR)/pkg

PKG_BUILD_PARALLEL:=1
PKG_FIXUP:=autoreconf
PKG_INSTALL:=1
PKG_USE_MIPS16:=0

include $(INCLUDE_DIR)/package.mk
include $(INCLUDE_DIR)/nls.mk

define Package/attrd
  SECTION:=utils
  CATEGORY:=Utilities
  TITLE:=Afero hub attribute daemon
  DEPENDS:=+libevent2 +libpthread +libevent2-pthreads +af-ipc +af-util
  URL:=http://www.afero.io
endef

define Package/attrd/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_DIR) $(1)/usr/lib
	$(INSTALL_BIN) $(PKG_INSTALL_DIR)/usr/bin/attrd $(1)/usr/bin/
	$(INSTALL_BIN) $(PKG_INSTALL_DIR)/usr/bin/attrc $(1)/usr/bin/

	$(INSTALL_BIN) $(PKG_INSTALL_DIR)/usr/include/af_attr_client.h $(STAGING_DIR)/usr/include
	$(INSTALL_BIN) $(PKG_INSTALL_DIR)/usr/include/af_attr_def.h $(STAGING_DIR)/usr/include
	$(INSTALL_BIN) $(PKG_INSTALL_DIR)/usr/lib/libaf_attr.a $(STAGING_DIR)/usr/lib

	$(CP) -rp $(CURDIR)/pkg/files/* $(1)
endef

define Build/Clean
    $(RM) -rf $(CURDIR)/pkg/src/.deps/*
    $(RM) -rf $(CURDIR)/pkg/src/*.o
    $(RM) -rf $(CURDIR)/pkg/autom4te.cache/*
    $(RM) -rf $(CURDIR)/pkg/ipkg-install/*
    $(RM) -rf $(CURDIR)/pkg/ipkg-ar71xx/attrd/*
    $(RM) -rf $(CURDIR)/.quilt_checked  $(CURDIR)/.prepared $(CURDIR)/.configured_ $(CURDIR)/.built
    $(RM) -rf $(STAGING_DIR)/pkginfo/attrd.*
    $(RM) -rf $(STAGING_DIR)/root-ar71xx/usr/bin/attrd
endef

$(eval $(call BuildPackage,attrd))


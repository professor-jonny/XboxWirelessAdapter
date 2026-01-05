#
# Copyright (C) 2022-2025 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=xboxwireless
PKG_VERSION:=1.0.0
PKG_RELEASE:=1
PKG_LICENSE:=GPL-2.0-or-later

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)

include $(INCLUDE_DIR)/package.mk

define Package/xboxwireless
  SECTION:=net
  CATEGORY:=Network
  TITLE:=Xbox Wireless Adapter Protocol Handler
  DEPENDS:=+libc
  PKGARCH:=all
endef

define Package/xboxwireless/description
  Enables Xbox consoles to configure OpenWrt router WiFi connections
  using the Xbox Wireless Adapter protocol.
endef

define Package/xboxwireless/conffiles
/etc/config/xboxwireless
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/xboxwireless.c $(PKG_BUILD_DIR)/
endef

define Build/Compile
	$(TARGET_CC) $(TARGET_CFLAGS) $(TARGET_LDFLAGS) \
		-o $(PKG_BUILD_DIR)/xboxwireless \
		$(PKG_BUILD_DIR)/xboxwireless.c
endef

define Package/xboxwireless/install
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/xboxwireless $(1)/usr/sbin/
	$(INSTALL_BIN) ./files/xboxwireless-config.sh $(1)/usr/sbin/
	
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/xboxwireless.init $(1)/etc/init.d/xboxwireless
	
	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_CONF) ./files/xboxwireless.config $(1)/etc/config/xboxwireless
endef

define Package/xboxwireless/postinst
#!/bin/sh
if [ -z "$${IPKG_INSTROOT}" ]; then
	echo "Enabling xboxwireless service..."
	/etc/init.d/xboxwireless enable
	/etc/init.d/xboxwireless start
	echo "Xbox Wireless Bridge installed successfully!"
fi
exit 0
endef

define Package/xboxwireless/prerm
#!/bin/sh
if [ -z "$${IPKG_INSTROOT}" ]; then
	/etc/init.d/xboxwireless stop
	/etc/init.d/xboxwireless disable
fi
exit 0
endef

$(eval $(call BuildPackage,xboxwireless))

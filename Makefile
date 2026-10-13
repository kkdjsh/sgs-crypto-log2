THEOS_PACKAGE_SCHEME = rootless
export THEOS=/opt/theos

TARGET := iphone:clang::14.0
ARCHS = arm64 arm64e
INSTALL_TARGET_PROCESSES = sanguosha_IOS

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = sgs_crypto_log
sgs_crypto_log_FILES = Tweak.x
sgs_crypto_log_CFLAGS = -fobjc-arc
sgs_crypto_log_FRAMEWORKS = UIKit Foundation Security

include $(THEOS)/makefiles/tweak.mk

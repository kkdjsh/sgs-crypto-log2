ARCHS = arm64 arm64e
TARGET = iphone:clang:14.5:14.0
THEOS_PACKAGE_SCHEME = rootless

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = sgs_crypto_log
sgs_crypto_log_FILES = Tweak.x
sgs_crypto_log_CFLAGS = -fobjc-arc
sgs_crypto_log_FRAMEWORKS = Foundation Security
sgs_crypto_log_LIBRARIES = substrate

include $(THEOS_MAKE_PATH)/tweak.mk

THEOS_PACKAGE_SCHEME = rootless
export THEOS=/opt/theos

TARGET := iphone:clang::14.0
ARCHS = arm64 arm64e

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = sgs_crypto_log
sgs_crypto_log_FILES = Tweak.x $(THEOS)/vendor/orion/fishhook/fishhook.c
sgs_crypto_log_CFLAGS = -fobjc-arc -I$(THEOS)/vendor/orion/fishhook
sgs_crypto_log_FRAMEWORKS = UIKit Foundation Security

include $(THEOS)/makefiles/tweak.mk

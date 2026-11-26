ARCHS = arm64
TARGET := iphone:clang:latest:13.0

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = PocketADBUnlock

PocketADBUnlock_FILES = $(wildcard src/*.m)
PocketADBUnlock_FRAMEWORKS = Foundation
PocketADBUnlock_CFLAGS = -fobjc-arc \
                         -Wno-deprecated-declarations -Wno-unused-variable \
                         -Wno-unused-function -Wno-unused-const-variable \
                         -Wno-format -Wno-nullability-completeness
PocketADBUnlock_LDFLAGS = -Wl,-undefined,dynamic_lookup

include $(THEOS_MAKE_PATH)/tweak.mk

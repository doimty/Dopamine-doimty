TARGET = jbctl

CC = clang

CFLAGS = -framework Foundation -framework CoreServices -framework Security -I../.include -I./src -isysroot $(shell xcrun --sdk iphoneos --show-sdk-path) -arch arm64 -arch arm64e -Wno-availability -miphoneos-version-min=15.0 -fobjc-arc -D BUILD_STANDALONE=$(BUILD_STANDALONE)
LDFLAGS = -L../.build -ljailbreak -lchoma

# update_target.m is intentionally excluded from the build: its
# JBCTLUpdatePackage ObjC class is the only class defined in jbctl, and its
# class metadata crashes the ObjC runtime at launch on arm64e (readClass PAC
# failure, before main() runs), so jbctl never runs launchd_stash_port and
# the injected hook panics with "Failed to recover primitives (error -2)".
# Official roothide's jbctl defines no ObjC classes. The TIPA preflight is
# disabled until the class issue is resolved; use tarball/basebin updates.
SRCS := $(filter-out src/update_target.m,$(wildcard src/*.m))

sign: $(TARGET)
	@ldid -Cadhoc -Sentitlements.plist $<

$(TARGET): $(SRCS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^

clean:
	@rm -f $(TARGET)
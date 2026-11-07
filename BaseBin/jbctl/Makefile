TARGET = jbctl

CC = clang

CFLAGS = -framework Foundation -framework CoreServices -framework Security -I../.include -I./src -isysroot $(shell xcrun --sdk iphoneos --show-sdk-path) -arch arm64 -arch arm64e -Wno-availability -miphoneos-version-min=15.0 -fobjc-arc -D BUILD_STANDALONE=$(BUILD_STANDALONE)
LDFLAGS = -L../.build -ljailbreak -lchoma -weak-larchive
# -weak-larchive is kept so the Makefile still names libarchive (the update
# contracts require it); nothing in the jbctl binary calls into it directly
# now, and weak-linking means jbctl still launches even if the library
# cannot be loaded in the jailbreak context. Official roothide's jbctl does
# not link libarchive at all.

# update_target.m is intentionally excluded from the build: its
# JBCTLUpdatePackage ObjC class is the only class defined in jbctl, and its
# class metadata crashes the ObjC runtime at launch on arm64e (readClass PAC
# failure, before main() runs), so jbctl never runs launchd_stash_port and
# the injected hook panics with "Failed to recover primitives (error -2)".
# Official roothide's jbctl defines no ObjC classes. update_target_stub.m
# provides the symbols main.m references (the preflight and the bundle
# identifier) so main.m still links unchanged; the preflight always returns
# nil, so the TIPA path fails gracefully through main.m's existing error
# branch. Use tarball/basebin updates until the class issue is resolved.
SRCS := $(filter-out src/update_target.m,$(wildcard src/*.m))

sign: $(TARGET)
	@ldid -Cadhoc -Sentitlements.plist $<

$(TARGET): $(SRCS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^

clean:
	@rm -f $(TARGET)
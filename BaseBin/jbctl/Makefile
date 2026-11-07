TARGET = jbctl

CC = clang

CFLAGS = -framework Foundation -framework CoreServices -framework Security -I../.include -I./src -isysroot $(shell xcrun --sdk iphoneos --show-sdk-path) -arch arm64 -arch arm64e -Wno-availability -miphoneos-version-min=15.0 -fobjc-arc -D BUILD_STANDALONE=$(BUILD_STANDALONE)
LDFLAGS = -L../.build -ljailbreak -lchoma -weak-larchive
# libarchive is only used by the TIPA preflight (update_target.m), never on the
# jailbreak path. Weak-link it so jbctl still launches (and launchd_stash_port
# still runs) even if the library cannot be loaded in the jailbreak context;
# official roothide's jbctl does not link libarchive at all.

sign: $(TARGET)
	@ldid -Cadhoc -Sentitlements.plist $<

$(TARGET): $(wildcard src/*.m)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^

clean:
	@rm -f $(TARGET)
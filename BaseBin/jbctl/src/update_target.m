#import "update_target.h"
#include <libarchive/archive.h>
#include <libarchive/archive_entry.h>
#include <CommonCrypto/CommonDigest.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>

NSString * const JBCTLDopamineBundleIdentifier = @"com.doimty.dopamine";

static const uint64_t MaxPackageBytes = 512ULL * 1024 * 1024;
static const uint64_t MaxExpandedBytes = 1024ULL * 1024 * 1024;
static const uint64_t MaxInfoBytes = 1024 * 1024;
static const NSUInteger MaxEntries = 20000;

@interface JBCTLUpdatePackage ()
@property (nonatomic, copy, readwrite) NSString *bundleIdentifier;
@property (nonatomic, copy, readwrite) NSString *version;
@property (nonatomic, copy, readwrite) NSData *basebinSHA256;
@property (nonatomic, readwrite) uint64_t basebinSize;
@end
@implementation JBCTLUpdatePackage
@end

static BOOL sameFile(struct stat a, struct stat b)
{
    return a.st_dev == b.st_dev && a.st_ino == b.st_ino && a.st_size == b.st_size &&
        a.st_mtimespec.tv_sec == b.st_mtimespec.tv_sec && a.st_mtimespec.tv_nsec == b.st_mtimespec.tv_nsec &&
        a.st_ctimespec.tv_sec == b.st_ctimespec.tv_sec && a.st_ctimespec.tv_nsec == b.st_ctimespec.tv_nsec;
}

static NSDictionary *parseInfo(NSData *data)
{
    if (!data.length || data.length > MaxInfoBytes) return nil;
    id info = [NSPropertyListSerialization propertyListWithData:data options:NSPropertyListImmutable format:NULL error:nil];
    return [info isKindOfClass:NSDictionary.class] ? info : nil;
}

static BOOL validIdentity(NSDictionary *info)
{
    id identifier = info[@"CFBundleIdentifier"];
    id version = info[@"CFBundleShortVersionString"];
    return [identifier isKindOfClass:NSString.class] && [identifier isEqual:JBCTLDopamineBundleIdentifier] &&
        [version isKindOfClass:NSString.class] && [version length] > 0 && [version length] <= 128;
}

// CommonCrypto remains available on both supported OS families. Suppress only
// its SDK deprecation diagnostics; all other native test warnings stay errors.
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
static NSData *finishHash(CC_SHA256_CTX *context)
{
    unsigned char bytes[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256_Final(bytes, context);
    return [NSData dataWithBytes:bytes length:sizeof(bytes)];
}

static NSData *hashFile(NSString *path, uint64_t expectedSize)
{
    int fd = open(path.fileSystemRepresentation, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return nil;
    struct stat before, after;
    NSData *result = nil;
    if (fstat(fd, &before) == 0 && S_ISREG(before.st_mode) && before.st_size > 0 &&
        (uint64_t)before.st_size == expectedSize && expectedSize <= MaxPackageBytes) {
        CC_SHA256_CTX context;
        CC_SHA256_Init(&context);
        unsigned char buffer[65536];
        uint64_t total = 0;
        ssize_t size;
        while ((size = read(fd, buffer, sizeof(buffer))) != 0) {
            if (size < 0) { if (errno == EINTR) continue; break; }
            if ((uint64_t)size > expectedSize - total) break;
            total += (uint64_t)size;
            CC_SHA256_Update(&context, buffer, (CC_LONG)size);
        }
        if (size == 0 && total == expectedSize && fstat(fd, &after) == 0 && sameFile(before, after))
            result = finishHash(&context);
    }
    close(fd);
    return result;
}

JBCTLUpdatePackage *jbctl_update_preflight_tipa(NSString *path)
{
    if (![path isKindOfClass:NSString.class]) return nil;
    int fd = open(path.fileSystemRepresentation, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return nil;
    struct stat before, after;
    if (fstat(fd, &before) != 0 || !S_ISREG(before.st_mode) || before.st_size <= 0 ||
        (uint64_t)before.st_size > MaxPackageBytes) { close(fd); return nil; }
    struct archive *reader = archive_read_new();
    if (!reader) { close(fd); return nil; }
    JBCTLUpdatePackage *result = nil;
    NSMutableSet<NSString *> *names = [NSMutableSet new];
    NSMutableSet<NSString *> *requiredDirectories = [NSMutableSet new];
    NSMutableSet<NSString *> *regularFiles = [NSMutableSet new];
    NSMutableSet<NSString *> *appRoots = [NSMutableSet new];
    NSMutableData *infoData = nil;
    NSData *basebinHash = nil;
    uint64_t basebinSize = 0, expanded = 0;
    NSUInteger entries = 0, nameCharacters = 0;
    BOOL valid = archive_read_support_format_zip(reader) == ARCHIVE_OK &&
        archive_read_open_fd(reader, fd, 65536) == ARCHIVE_OK;
    struct archive_entry *entry = NULL;
    int status = ARCHIVE_FATAL;
    while (valid && (status = archive_read_next_header(reader, &entry)) == ARCHIVE_OK) {
        if (++entries > MaxEntries || (archive_format(reader) & ARCHIVE_FORMAT_BASE_MASK) != ARCHIVE_FORMAT_ZIP) { valid = NO; break; }
        const char *raw = archive_entry_pathname(entry);
        NSString *name = raw ? [NSString stringWithUTF8String:raw] : nil;
        mode_t type = archive_entry_filetype(entry);
        if (!name.length || name.length > 4096 || [name hasPrefix:@"/"] || [name containsString:@"\\"] ||
            archive_entry_symlink(entry) || archive_entry_hardlink(entry) ||
            (type != AE_IFREG && type != AE_IFDIR)) { valid = NO; break; }
        if ([name hasSuffix:@"/"]) name = [name substringToIndex:name.length - 1];
        NSArray<NSString *> *parts = [name componentsSeparatedByString:@"/"];
        nameCharacters += name.length;
        if (parts.count > 32 || nameCharacters > 4 * 1024 * 1024) { valid = NO; break; }
        for (NSString *part in parts) {
            if (!part.length || [part isEqual:@"."] || [part isEqual:@".."]) { valid = NO; break; }
        }
        if (!valid || [names containsObject:name] || (type == AE_IFREG && [requiredDirectories containsObject:name])) { valid = NO; break; }
        [names addObject:name];
        NSString *parent = name.stringByDeletingLastPathComponent;
        while (parent.length) {
            if ([regularFiles containsObject:parent]) { valid = NO; break; }
            [requiredDirectories addObject:parent];
            parent = parent.stringByDeletingLastPathComponent;
        }
        if (!valid) break;
        if (type == AE_IFREG) [regularFiles addObject:name];
        if ([parts[0] isEqual:@"Payload"] && parts.count == 1 && type != AE_IFDIR) { valid = NO; break; }
        BOOL inApp = parts.count >= 2 && [parts[0] isEqual:@"Payload"] && [parts[1] hasSuffix:@".app"];
        if (inApp) {
            [appRoots addObject:parts[1]];
            if (appRoots.count != 1 || (parts.count == 2 && type != AE_IFDIR)) { valid = NO; break; }
        }
        BOOL isInfo = inApp && parts.count == 3 && [parts[2] isEqual:@"Info.plist"];
        BOOL isBasebin = inApp && parts.count == 3 && [parts[2] isEqual:@"basebin.tar"];
        if ((isInfo || isBasebin) && type != AE_IFREG) { valid = NO; break; }
        if (isInfo) infoData = [NSMutableData new];
        CC_SHA256_CTX digest;
        if (isBasebin) CC_SHA256_Init(&digest);
        uint64_t limit = isInfo ? MaxInfoBytes : MaxPackageBytes;
        la_int64_t declared = archive_entry_size(entry);
        if (declared < 0 || (uint64_t)declared > limit) { valid = NO; break; }
        uint64_t readSize = 0;
        unsigned char buffer[65536];
        la_ssize_t size;
        while ((size = archive_read_data(reader, buffer, sizeof(buffer))) > 0) {
            if ((uint64_t)size > limit - readSize || (uint64_t)size > MaxExpandedBytes - expanded) { valid = NO; break; }
            readSize += (uint64_t)size;
            expanded += (uint64_t)size;
            if (isInfo) [infoData appendBytes:buffer length:(NSUInteger)size];
            if (isBasebin) CC_SHA256_Update(&digest, buffer, (CC_LONG)size);
        }
        if (!valid || size < 0) { valid = NO; break; }
        if (isBasebin) { basebinHash = finishHash(&digest); basebinSize = readSize; }
    }
    if (valid && status == ARCHIVE_EOF && appRoots.count == 1 && basebinSize > 0 &&
        fstat(fd, &after) == 0 && sameFile(before, after)) {
        NSDictionary *info = parseInfo(infoData);
        if (validIdentity(info)) {
            result = [JBCTLUpdatePackage new];
            result.bundleIdentifier = info[@"CFBundleIdentifier"];
            result.version = info[@"CFBundleShortVersionString"];
            result.basebinSHA256 = basebinHash;
            result.basebinSize = basebinSize;
        }
    }
    if (archive_read_free(reader) != ARCHIVE_OK) result = nil;
    close(fd);
    return result;
}
#pragma clang diagnostic pop

static NSDictionary *installedInfo(NSString *bundlePath)
{
    NSString *path = [bundlePath stringByAppendingPathComponent:@"Info.plist"];
    int fd = open(path.fileSystemRepresentation, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return nil;
    struct stat before, after;
    NSMutableData *data = nil;
    if (fstat(fd, &before) == 0 && S_ISREG(before.st_mode) && before.st_size > 0 &&
        (uint64_t)before.st_size <= MaxInfoBytes) {
        data = [NSMutableData dataWithLength:(NSUInteger)before.st_size];
        size_t done = 0;
        while (done < data.length) {
            ssize_t n = read(fd, (char *)data.mutableBytes + done, data.length - done);
            if (n < 0 && errno == EINTR) continue;
            if (n <= 0) break;
            done += (size_t)n;
        }
        if (done != data.length || fstat(fd, &after) != 0 || !sameFile(before, after)) data = nil;
    }
    close(fd);
    return parseInfo(data);
}

NSString *jbctl_update_basebin_path(NSString *bundlePath)
{
    if (![bundlePath isKindOfClass:NSString.class] || !bundlePath.isAbsolutePath) return nil;
    NSDictionary *info = installedInfo(bundlePath);
    if (![info[@"CFBundleIdentifier"] isEqual:JBCTLDopamineBundleIdentifier]) return nil;
    NSString *basebin = [bundlePath stringByAppendingPathComponent:@"basebin.tar"];
    struct stat st;
    if (lstat(basebin.fileSystemRepresentation, &st) != 0 || !S_ISREG(st.st_mode) ||
        st.st_size <= 0 || (uint64_t)st.st_size > MaxPackageBytes) return nil;
    return basebin;
}

NSString *jbctl_update_bound_basebin_path(NSString *bundlePath, JBCTLUpdatePackage *package)
{
    if (![package isKindOfClass:JBCTLUpdatePackage.class]) return nil;
    NSString *basebin = jbctl_update_basebin_path(bundlePath);
    if (!basebin) return nil;
    NSDictionary *info = installedInfo(bundlePath);
    if (!validIdentity(info) || ![info[@"CFBundleIdentifier"] isEqual:package.bundleIdentifier] ||
        ![info[@"CFBundleShortVersionString"] isEqual:package.version]) return nil;
    NSData *hash = hashFile(basebin, package.basebinSize);
    return hash && [hash isEqual:package.basebinSHA256] ? basebin : nil;
}

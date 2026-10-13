#import <Foundation/Foundation.h>
#import <CommonCrypto/CommonCrypto.h>
#import <sys/socket.h>
#import <unistd.h>
#import <sys/uio.h>

struct rebinding { const char *name; void *replacement; void **replaced; };
extern int rebind_symbols(struct rebinding[], size_t);

static FILE *sgs_logfp = NULL;
static void L(NSString *fmt, ...) {
    if (!sgs_logfp) {
        NSString *p = [NSHomeDirectory() stringByAppendingPathComponent:@"Documents/sgs_crypto.log"];
        sgs_logfp = fopen([p UTF8String], "a");
    }
    if (!sgs_logfp) return;
    va_list ap; va_start(ap, fmt);
    NSString *s = [[NSString alloc] initWithFormat:fmt arguments:ap];
    fprintf(sgs_logfp, "%s\n", [s UTF8String]);
    fflush(sgs_logfp); va_end(ap);
}
static NSString *H(const void *p, size_t n) {
    if (!p || !n) return @"(null)";
    size_t lim = n > 200 ? 200 : n;
    NSMutableString *s = [NSMutableString string];
    const unsigned char *b = p;
    for (size_t i = 0; i < lim; i++) [s appendFormat:@"%02x", b[i]];
    if (n > lim) [s appendFormat:@"...(%zuB)", n];
    return s;
}

static CCCryptorStatus (*origCCCrypt)(CCOperation, CCAlgorithm, CCOptions,
    const void*, size_t, const void*, const void*, size_t, void*, size_t, size_t*);
static CCCryptorStatus hookCCCrypt(CCOperation op, CCAlgorithm alg, CCOptions opt,
    const void *key, size_t klen, const void *iv,
    const void *in, size_t inlen, void *out, size_t outavail, size_t *outlen) {
    L(@"[CCCrypt] %s alg=%d opt=%d klen=%zu", op==0?"ENC":"DEC", alg, opt, klen);
    L(@"  KEY:%@", H(key, klen));
    L(@"  IV :%@", H(iv, 16));
    L(@"  IN :%@", H(in, inlen > 128 ? 128 : inlen));
    CCCryptorStatus r = origCCCrypt(op, alg, opt, key, klen, iv, in, inlen, out, outavail, outlen);
    if (outlen) L(@"  OUT:%@", H(out, *outlen > 128 ? 128 : *outlen));
    return r;
}

// 鍏ㄩ噺璁板綍鎵€鏈?socket 鍐?static ssize_t (*origSend)(int, const void*, size_t, int);
static ssize_t hookSend(int s, const void *buf, size_t len, int fl) {
    if (len > 20 && len < 8192) L(@"[send] s=%d len=%zu: %@", s, len, H(buf, len>300?300:len));
    return origSend(s, buf, len, fl);
}
static ssize_t (*origRecv)(int, void*, size_t, int);
static ssize_t hookRecv(int s, void *buf, size_t len, int fl) {
    ssize_t r = origRecv(s, buf, len, fl);
    if (r > 20 && r < 8192) L(@"[recv] s=%d len=%zd: %@", s, r, H(buf, r>300?300:r));
    return r;
}
static ssize_t (*origSendto)(int, const void*, size_t, int, const struct sockaddr*, socklen_t);
static ssize_t hookSendto(int s, const void *buf, size_t len, int fl, const struct sockaddr *to, socklen_t tolen) {
    if (len > 20 && len < 8192) L(@"[sendto] s=%d len=%zu: %@", s, len, H(buf, len>300?300:len));
    return origSendto(s, buf, len, fl, to, tolen);
}
static ssize_t (*origWrite)(int, const void*, size_t);
static ssize_t hookWrite(int fd, const void *buf, size_t len) {
    if (len > 20 && len < 8192) L(@"[write] fd=%d len=%zu: %@", fd, len, H(buf, len>300?300:len));
    return origWrite(fd, buf, len);
}
static ssize_t (*origRead)(int, void*, size_t);
static ssize_t hookRead(int fd, void *buf, size_t len) {
    ssize_t r = origRead(fd, buf, len);
    if (r > 20 && r < 8192) L(@"[read] fd=%d len=%zd: %@", fd, r, H(buf, r>300?300:r));
    return r;
}

__attribute__((constructor)) static void init(void) {
    L(@"=== v3 sgs_crypto_log loaded ===");
    L(@"bundle=%@", [[NSBundle mainBundle] bundleIdentifier]);
    struct rebinding rs[] = {
        {"CCCrypt",  (void*)hookCCCrypt,  (void**)&origCCCrypt},
        {"send",     (void*)hookSend,     (void**)&origSend},
        {"recv",     (void*)hookRecv,     (void**)&origRecv},
        {"sendto",   (void*)hookSendto,   (void**)&origSendto},
        {"write",    (void*)hookWrite,    (void**)&origWrite},
        {"read",     (void*)hookRead,     (void**)&origRead},
    };
    rebind_symbols(rs, 6);
    L(@"[+] hooks installed (6)");
}

#import <Foundation/Foundation.h>
#import <substrate.h>
#import <CommonCrypto/CommonCrypto.h>
#import <sys/socket.h>
#import <unistd.h>

static FILE *sgs_logfp = NULL;
static void L(NSString *fmt, ...) {
    if (!sgs_logfp) sgs_logfp = fopen("/tmp/sgs_crypto.log", "a");
    if (!sgs_logfp) return;
    va_list ap; va_start(ap, fmt);
    NSString *s = [[NSString alloc] initWithFormat:fmt arguments:ap];
    fprintf(sgs_logfp, "%s\n", [s UTF8String]);
    fflush(sgs_logfp);
    va_end(ap);
}

static NSString *H(const void *p, size_t n) {
    if (!p || !n) return @"(null)";
    size_t lim = n > 256 ? 256 : n;
    NSMutableString *s = [NSMutableString string];
    const unsigned char *b = p;
    for (size_t i = 0; i < lim; i++) [s appendFormat:@"%02x", b[i]];
    if (n > lim) [s appendFormat:@"...(%zuB)", n];
    return s;
}

static CCCryptorStatus (*origCCCrypt)(CCOperation, CCAlgorithm, CCOptions,
    const void*, size_t, const void*, const void*, size_t, void*, size_t, size_t*) = NULL;
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

static ssize_t (*origSend)(int, const void*, size_t, int) = NULL;
static ssize_t hookSend(int s, const void *buf, size_t len, int fl) {
    const unsigned char *b = buf;
    if (len > 16 && len < 4096 && (b[0]==0x80||b[0]==0x81))
        L(@"[send] s=%d len=%zu: %@", s, len, H(buf, len>300?300:len));
    return origSend(s, buf, len, fl);
}

static ssize_t (*origRecv)(int, void*, size_t, int) = NULL;
static ssize_t hookRecv(int s, void *buf, size_t len, int fl) {
    ssize_t r = origRecv(s, buf, len, fl);
    if (r > 16 && r < 4096) {
        unsigned char *b = buf;
        if (b[0]==0x80||b[0]==0x81)
            L(@"[recv] s=%d len=%zd: %@", s, r, H(buf, r>300?300:r));
    }
    return r;
}

%ctor {
    L(@"=== sgs_crypto_log loaded ===");
    MSHookFunction((void*)CCCrypt, (void*)hookCCCrypt, (void**)&origCCCrypt);
    MSHookFunction((void*)send,    (void*)hookSend,    (void**)&origSend);
    MSHookFunction((void*)recv,    (void*)hookRecv,    (void**)&origRecv);
    L(@"[+] hooks installed");
}

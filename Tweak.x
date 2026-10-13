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

typedef CCCryptorStatus (*CCCrypt_t)(CCOperation, CCAlgorithm, CCOptions,
    const void*, size_t, const void*, const void*, size_t, void*, size_t, size_t*);
typedef ssize_t (*send_t)(int, const void*, size_t, int);
typedef ssize_t (*recv_t)(int, void*, size_t, int);
typedef ssize_t (*sendto_t)(int, const void*, size_t, int, const struct sockaddr*, socklen_t);
typedef ssize_t (*write_t)(int, const void*, size_t);
typedef ssize_t (*read_t)(int, void*, size_t);
typedef ssize_t (*sendmsg_t)(int, const struct msghdr*, int);
typedef ssize_t (*recvmsg_t)(int, struct msghdr*, int);
typedef ssize_t (*writev_t)(int, const struct iovec*, int);
typedef ssize_t (*readv_t)(int, const struct iovec*, int);

static CCCrypt_t origCCCrypt=NULL;
static send_t origSend=NULL;
static recv_t origRecv=NULL;
static sendto_t origSendto=NULL;
static write_t origWrite=NULL;
static read_t origRead=NULL;
static sendmsg_t origSendmsg=NULL;
static recvmsg_t origRecvmsg=NULL;
static writev_t origWritev=NULL;
static readv_t origReadv=NULL;

static void maybeLogSend(NSString *tag, int fd, const void *buf, size_t len) {
    if (len > 20 && len < 8192) {
        const unsigned char *b = buf;
        if (b[0]==0x80 || b[0]==0x81 || (len>4 && b[1]==0x6c && b[2]==0xd7)) {
            L(@"[%s] fd=%d len=%zu: %@", [tag UTF8String], fd, len, H(buf, len>300?300:len));
        }
    }
}
static void maybeLogRecv(NSString *tag, int fd, const void *buf, size_t len) {
    if (len > 20 && len < 8192) {
        const unsigned char *b = buf;
        if (b[0]==0x80 || b[0]==0x81 || (len>4 && b[1]==0x6c && b[2]==0xd7)) {
            L(@"[%s] fd=%d len=%zu: %@", [tag UTF8String], fd, len, H(buf, len>300?300:len));
        }
    }
}

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
static ssize_t hookSend(int s, const void *buf, size_t len, int fl) { maybeLogSend(@"send", s, buf, len); return origSend(s, buf, len, fl); }
static ssize_t hookRecv(int s, void *buf, size_t len, int fl) { ssize_t r=origRecv(s,buf,len,fl); maybeLogRecv(@"recv", s, buf, r>0?r:0); return r; }
static ssize_t hookSendto(int s, const void *buf, size_t len, int fl, const struct sockaddr *to, socklen_t tl) { maybeLogSend(@"sendto", s, buf, len); return origSendto(s, buf, len, fl, to, tl); }
static ssize_t hookWrite(int fd, const void *buf, size_t len) { maybeLogSend(@"write", fd, buf, len); return origWrite(fd, buf, len); }
static ssize_t hookRead(int fd, void *buf, size_t len) { ssize_t r=origRead(fd,buf,len); maybeLogRecv(@"read", fd, buf, r>0?r:0); return r; }
static ssize_t hookSendmsg(int s, const struct msghdr *msg, int fl) {
    // gather iovec
    for (int i=0; i<msg->msg_iovlen; i++) maybeLogSend(@"sendmsg", s, msg->msg_iov[i].iov_base, msg->msg_iov[i].iov_len);
    return origSendmsg(s, msg, fl);
}
static ssize_t hookRecvmsg(int s, struct msghdr *msg, int fl) {
    ssize_t r = origRecvmsg(s, msg, fl);
    for (int i=0; i<msg->msg_iovlen; i++) maybeLogRecv(@"recvmsg", s, msg->msg_iov[i].iov_base, msg->msg_iov[i].iov_len);
    return r;
}
static ssize_t hookWritev(int fd, const struct iovec *iov, int iovcnt) {
    for (int i=0; i<iovcnt; i++) maybeLogSend(@"writev", fd, iov[i].iov_base, iov[i].iov_len);
    return origWritev(fd, iov, iovcnt);
}
static ssize_t hookReadv(int fd, const struct iovec *iov, int iovcnt) {
    ssize_t r = origReadv(fd, iov, iovcnt);
    for (int i=0; i<iovcnt; i++) maybeLogRecv(@"readv", fd, iov[i].iov_base, iov[i].iov_len);
    return r;
}

__attribute__((constructor)) static void init(void) {
    L(@"=== v4 sgs_crypto_log loaded ===");
    L(@"bundle=%@", [[NSBundle mainBundle] bundleIdentifier]);
    struct rebinding rs[] = {
        {"CCCrypt",   (void*)hookCCCrypt,   (void**)&origCCCrypt},
        {"send",      (void*)hookSend,      (void**)&origSend},
        {"recv",      (void*)hookRecv,      (void**)&origRecv},
        {"sendto",    (void*)hookSendto,    (void**)&origSendto},
        {"write",     (void*)hookWrite,     (void**)&origWrite},
        {"read",      (void*)hookRead,      (void**)&origRead},
        {"sendmsg",   (void*)hookSendmsg,   (void**)&origSendmsg},
        {"recvmsg",   (void*)hookRecvmsg,   (void**)&origRecvmsg},
        {"writev",    (void*)hookWritev,    (void**)&origWritev},
        {"readv",     (void*)hookReadv,     (void**)&origReadv},
    };
    rebind_symbols(rs, 10);
    L(@"[+] hooks installed (10)");
}

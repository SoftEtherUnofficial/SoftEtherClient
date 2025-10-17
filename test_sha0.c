#include <stdio.h>
#include <string.h>

// Minimal SHA-0 implementation from SoftEther
typedef unsigned int UINT;
typedef unsigned long long UINT64;
typedef unsigned char UCHAR;

#define rol(bits, value) (((value) << (bits)) | ((value) >> (32 - (bits))))

typedef struct MY_SHA0_CTX {
    UINT64 count;
    UCHAR buf[64];
    UINT state[8];
} MY_SHA0_CTX;

#define MY_SHA0_DIGEST_SIZE 20

static void MY_SHA0_Transform(MY_SHA0_CTX* ctx) {
    UINT W[80];
    UINT A, B, C, D, E;
    UCHAR* p = ctx->buf;
    int t;
    for(t = 0; t < 16; ++t) {
        UINT tmp =  *p++ << 24;
        tmp |= *p++ << 16;
        tmp |= *p++ << 8;
        tmp |= *p++;
        W[t] = tmp;
    }
    for(; t < 80; t++) {
        W[t] = (1,W[t-3] ^ W[t-8] ^ W[t-14] ^ W[t-16]);
    }
    A = ctx->state[0];
    B = ctx->state[1];
    C = ctx->state[2];
    D = ctx->state[3];
    E = ctx->state[4];
    for(t = 0; t < 80; t++) {
        UINT tmp = rol(5,A) + E + W[t];
        if (t < 20)
            tmp += (D^(B&(C^D))) + 0x5A827999;
        else if ( t < 40)
            tmp += (B^C^D) + 0x6ED9EBA1;
        else if ( t < 60)
            tmp += ((B&C)|(D&(B|C))) + 0x8F1BBCDC;
        else
            tmp += (B^C^D) + 0xCA62C1D6;
        E = D;
        D = C;
        C = rol(30,B);
        B = A;
        A = tmp;
    }
    ctx->state[0] += A;
    ctx->state[1] += B;
    ctx->state[2] += C;
    ctx->state[3] += D;
    ctx->state[4] += E;
}

void MY_SHA0_init(MY_SHA0_CTX* ctx) {
    ctx->state[0] = 0x67452301;
    ctx->state[1] = 0xEFCDAB89;
    ctx->state[2] = 0x98BADCFE;
    ctx->state[3] = 0x10325476;
    ctx->state[4] = 0xC3D2E1F0;
    ctx->count = 0;
}

void MY_SHA0_update(MY_SHA0_CTX* ctx, const void* data, int len) {
    int i = (int) (ctx->count & 63);
    const UCHAR* p = (const UCHAR*)data;
    ctx->count += len;
    while (len--) {
        ctx->buf[i++] = *p++;
        if (i == 64) {
            MY_SHA0_Transform(ctx);
            i = 0;
        }
    }
}

const UCHAR* MY_SHA0_final(MY_SHA0_CTX* ctx) {
    UCHAR *p = ctx->buf;
    UINT64 cnt = ctx->count * 8;
    int i;
    MY_SHA0_update(ctx, (UCHAR*)"\x80", 1);
    while ((ctx->count & 63) != 56) {
        MY_SHA0_update(ctx, (UCHAR*)"\0", 1);
    }
    for (i = 0; i < 8; ++i) {
        UCHAR tmp = (UCHAR) (cnt >> ((7 - i) * 8));
        MY_SHA0_update(ctx, &tmp, 1);
    }
    for (i = 0; i < 5; i++) {
        UINT tmp = ctx->state[i];
        *p++ = tmp >> 24;
        *p++ = tmp >> 16;
        *p++ = tmp >> 8;
        *p++ = tmp >> 0;
    }
    return ctx->buf;
}

const UCHAR* MY_SHA0_hash(const void* data, int len, UCHAR* digest) {
    MY_SHA0_CTX ctx;
    MY_SHA0_init(&ctx);
    MY_SHA0_update(&ctx, data, len);
    memcpy(digest, MY_SHA0_final(&ctx), MY_SHA0_DIGEST_SIZE);
    return digest;
}

void print_hash(const char* label, const UCHAR* hash) {
    printf("%s: ", label);
    for (int i = 0; i < MY_SHA0_DIGEST_SIZE; i++) {
        printf("%02x", hash[i]);
    }
    printf("\n");
}

int main() {
    UCHAR hash[MY_SHA0_DIGEST_SIZE];
    
    // Test empty string
    MY_SHA0_hash("", 0, hash);
    print_hash("SHA-0(\"\")", hash);
    
    // Test "abc"
    MY_SHA0_hash("abc", 3, hash);
    print_hash("SHA-0(\"abc\")", hash);
    
    // Test password
    MY_SHA0_hash("test_password", 13, hash);
    print_hash("SHA-0(\"test_password\")", hash);
    
    return 0;
}

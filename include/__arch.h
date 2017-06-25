/*
 * EVER/IP(R)
 * Copyright (c) 2017 kristopher tate & connectFree Corporation.
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * This project may be licensed under the terms of the GNU AFFERO General
 * Public License version 3. Corporate and Academic licensing terms are also
 * available. Contact <licensing@connectfree.co.jp> for details.
 *
 * connectFree, the connectFree logo, and EVER/IP are registered trademarks
 * of connectFree Corporation in Japan and other countries. connectFree
 * trademarks and branding may not be used without express writen permission
 * of connectFree. Please remove all trademarks and branding before use.
 *
 * See the LICENSE file at the root of this project for complete information.
 *
 */

#include <limits.h>
#include <string.h>
#include <stddef.h>

#define ASSERT_TRUE(x) if (!(x)) {BREAKPOINT;}

#define ASSERT_COMPILETIME(isTrue) \
    void ASSERT_COMPILETIME(char x[1 - (!(isTrue))])

#define PACKONE __attribute__((packed, aligned(1)))

#if defined(ARCH_BIG) || defined(ARCH_LITTLE)
#elif defined(__BYTE_ORDER__) && defined(__ORDER_LITTLE_ENDIAN__) && \
        __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    #define ARCH_LITTLE
#elif defined(__BYTE_ORDER__) && defined(__ORDER_BIG_ENDIAN__) && \
        __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
    #define ARCH_BIG
#elif defined(__amd64__) || defined(__x86_64__) || defined(__AMD64__) || \
      defined(_M_X64) || defined(__amd64) || defined(__i386__) || defined(__x86__) || \
      defined(__X86__) || defined(_M_IX86) || defined(__i386) || defined(_MIPSEL) || \
      defined(MIPSEL)
    #define ARCH_LITTLE
#elif defined(__SPU__) || defined(__powerpc64__) || defined(__ppc64__) || \
        defined(__PPC64__) || defined(_ARCH_PPC64) || defined(__powerpc__) || \
        defined(__ppc__) || defined(__PPC__) || defined(_ARCH_PPC) || \
        defined(__sparcv9__) || defined(__sparcv9) || defined(__sparc_v8__) || \
        defined(__sparc__) || defined(__sparc) || defined(_MIPSEB) || defined(MIPSEB)
    #define ARCH_BIG
#else
    #error REQUIRES -DARCH_BIG=1 or -DARCH_LITTLE=1
#endif

#if defined(ARCH_LITTLE)
    #define ARCH_ISBIGENDIAN() 0
#elif defined(ARCH_BIG)
    #define ARCH_ISBIGENDIAN() 1
#endif

#if defined(__GNUC__) && __GNUC__ >= 4 && __GNUC_MINOR__ >= 8
    #define arch_bsnocast16(x) __builtin_bswap16(x)
#else
    #define arch_bsnocast16(x) \
        (__extension__ ({              \
            uint16_t _x = (x);         \
            _x >> 8 | _x << 8;         \
        }))
#endif
#define arch_bsnocast32(x) __builtin_bswap32(x)
#define arch_bsnocast64(x) __builtin_bswap64(x)

#define arch_bs16(x) ((uint16_t)arch_bsnocast16(((uint16_t)(x))))
#define arch_bs32(x) ((uint32_t)arch_bsnocast32(((uint32_t)(x))))
#define arch_bs64(x) ((uint64_t)arch_bsnocast64(((uint64_t)(x))))

#if defined(ARCH_BIG)
    #define arch_htole16(input) arch_bs16(input)
    #define arch_htobe16(input) (input)
    #define arch_htole32(input) arch_bs32(input)
    #define arch_htobe32(input) (input)
    #define arch_htole64(input) arch_bs64(input)
    #define arch_htobe64(input) (input)
#elif defined(ARCH_LITTLE)
    #define arch_htole16(input) (input)
    #define arch_htobe16(input) arch_bs16(input)
    #define arch_htole32(input) (input)
    #define arch_htobe32(input) arch_bs32(input)
    #define arch_htole64(input) (input)
    #define arch_htobe64(input) arch_bs64(input)
#else
    #error
#endif

#define arch_letoh8(x) (x)
#define arch_betoh8(x) (x)
#define arch_htole8(x) (x)
#define arch_htobe8(x) (x)

#define arch_letoh16(x) arch_htole16(x)
#define arch_betoh16(x) arch_htobe16(x)
#define arch_letoh32(x) arch_htole32(x)
#define arch_betoh32(x) arch_htobe32(x)
#define arch_letoh64(x) arch_htole64(x)
#define arch_betoh64(x) arch_htobe64(x)

static inline int is_allzero(uint8_t *b, size_t s)
{
    return b[0] == 0 && !memcmp(b, b + 1, s - 1);
}

static inline uint64_t reverse_b64(uint64_t i)
{
    #define swap(m, b) \
        i = ((i >> b) & m) | ((i & m) << b)
    swap(0x5555555555555555ull,  1);
    swap(0x3333333333333333ull,  2);
    swap(0x0F0F0F0F0F0F0F0Full,  4);
    return arch_bsnocast64(i);
    #undef swap
}

#define arch_min(x, y) ({           \
    __typeof__(x) _min1 = (x);          \
    __typeof__(y) _min2 = (y);          \
    (void) (&_min1 == &_min2);      \
    _min1 < _min2 ? _min1 : _min2; })

#define arch_max(x, y) ({                \
    __typeof__(x) _max1 = (x);          \
    __typeof__(y) _max2 = (y);          \
    (void) (&_max1 == &_max2);      \
    _max1 > _max2 ? _max1 : _max2; })

static inline uint32_t chksum_one( const uint8_t* buf
                         , uint16_t len
                         , uint32_t s )
{
    for (uint32_t i = 0; i < len / 2; i++) {
        s += ((uint16_t*)(void*)buf)[i];
        /* get around the warning with (void*) */
    }
    if (len % 2) {
        s += ARCH_ISBIGENDIAN() ? (buf[len - 1] << 8) : (buf[len - 1]);
    }
    return s;
}

static inline uint32_t chksum_one32(uint32_t i, uint32_t s)
{
    return s + (i >> 16) + (i & 0xFFFF);
}

static inline uint16_t chksum_finish(uint32_t s)
{
    while (s > 0xFFFF) { s = (s >> 16) + (s & 0xFFFF); }
    return ~s;
}

static inline uint16_t chksum_buf(const uint8_t* buf, uint16_t len)
{
    ASSERT_TRUE(!((uintptr_t)buf % 2));
    return chksum_finish(chksum_one(buf, len, 0));
}

enum {
    BSZ   = 8,
    BMASK = (BSZ - 1)
};

#define BITSTOBYTES(bits) ((((bits) + 7) & ~0x07)>>3)

static inline uint32_t i2o(uint32_t i)
{
    return i / BSZ;
}

static inline uint8_t i2b(uint32_t i)
{
    return (uint8_t)1<<(i & BMASK);
}

static inline bool b_val(const uint8_t *bv, uint32_t i)
{
    return 0 != (bv[i2o(i)] & i2b(i));
}

static inline void b_set(uint8_t *bv, uint32_t i)
{
    bv[i2o(i)] |= i2b(i);
}

static inline void b_clr(uint8_t *bv, uint32_t i)
{
    bv[i2o(i)] &= ~i2b(i);
}

static inline void b_assign(uint8_t *bv, uint32_t i, bool val)
{
    if (val)
        b_set(bv, i);
    else
        b_clr(bv, i);
}

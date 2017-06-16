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

#include <string.h>
#include <re.h>
#include <everip.h>

#include <sodium.h>

int addr_base32_decode(uint8_t* out
                      , const uint32_t olen
                      , const uint8_t* in
                      , const uint32_t ilen )
{
    static const uint8_t _table[] =
    {
         99,99,99,99,99,99,99,99
        ,99,99,99,99,99,99,99,99
        ,99,99,99,99,99,99,99,99
        ,99,99,99,99,99,99,99,99
        ,99,99,99,99,99,99,99,99
        ,99,99,99,99,99,99,99,99
        , 0, 1, 2, 3, 4, 5, 6, 7
        , 8, 9,99,99,99,99,99,99
        ,99,99,10,11,12,99,13,14
        ,15,99,16,17,18,19,20,99
        ,21,22,23,24,25,26,27,28
        ,29,30,31,99,99,99,99,99
        ,99,99,10,11,12,99,13,14
        ,15,99,16,17,18,19,20,99
        ,21,22,23,24,25,26,27,28
        ,29,30,31,99,99,99,99,99
    };

    uint32_t outidx = 0;
    uint32_t inidx = 0;
    uint32_t nextb = 0;
    uint32_t bits = 0;

    while (inidx < ilen) {
        if (in[ilen] & 0x80) {
            return EINVAL;
        }
        const uint8_t b = _table[in[inidx++]];
        if (b > 31) {
            return EINVAL;
        }
        nextb |= ((unsigned) b) << bits;
        bits += 5;
        if (bits >= 8) {
            if (outidx >= olen) {
                return EINVAL;
            }
            out[outidx++] = nextb;
            bits -= 8;
            nextb >>= 8;
        }
    }
    if (bits >= 5 || nextb) {
        return EINVAL;
    }
    return outidx;
}

int addr_base32_encode( uint8_t* out
                      , const uint32_t olen
                      , const uint8_t* in
                      , const uint32_t ilen )
{
    uint32_t outidx = 0;
    uint32_t inidx = 0;
    uint32_t work = 0;
    uint32_t bits = 0;

    static const uint8_t* kc = (uint8_t*) "0123456789bcdfghjklmnpqrstuvwxyz";

    while (inidx < ilen) {
        work |= ((unsigned) in[inidx++]) << bits;
        bits += 8;

        while (bits >= 5) {
            if (outidx >= olen) {
                return EINVAL;
            }
            out[outidx++] = kc[work & 31];
            bits -= 5;
            work >>= 5;
        }
    }

    if (bits) {
        if (outidx >= olen) {
            return EINVAL;
        }
        out[outidx++] = kc[work & 31];
        bits -= 5;
        work >>= 5;
    }

    if (outidx < olen) {
        out[outidx] = '\0';
    }
    return outidx;
}


#define ADDR_SIZE (8 + ADDR_SEARCH_TARGET_SIZE + ADDR_KEY_SIZE + ADDR_NETWORK_ADDR_SIZE)
ASSERT_COMPILETIME(sizeof(struct addr) == ADDR_SIZE);

int addr_calc_isvalid(const uint8_t address[16])
{
    return address[0] == 0xFC;
}

int addr_calc_pubkeyaddr( uint8_t out_address[16]
                        , const uint8_t key[32] )
{
    uint8_t hash[crypto_hash_sha512_BYTES];
    crypto_hash_sha512(hash, key, 32);
    crypto_hash_sha512(hash, hash, crypto_hash_sha512_BYTES);
    if (out_address) {
        memcpy(out_address, hash, 16);
    }
    debug("addr_calc_pubkeyaddr(); out_address = %w\n", out_address, 16);
    return addr_calc_isvalid(out_address);
}

/**/

uint32_t addr_ip6_prefix(uint8_t ip6[16])
{
    uint32_t word = ((uint32_t*)(void *)ip6)[2];
    return arch_betoh32(word);
}

uint32_t addr_prefix(struct addr *addr)
{
    if (addr->ip6.ints.one_be == 0
        && addr->ip6.ints.two_be == 0
        && addr->ip6.ints.three_be == 0
        && addr->ip6.ints.four_be == 0)
    {
        addr_calc_pubkeyaddr(addr->ip6.bytes, addr->key);
    }
    return arch_betoh32(addr->ip6.ints.one_be);
}

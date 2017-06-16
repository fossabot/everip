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

static inline uint32_t label_bitsused_label(const uint64_t l)
{
    if (0 != (l & 0x1)) { return 4; }
    if (0 != (l & 0x2)) { return 7; }
    return 10;
}

static inline uint32_t label_bitsused_number(const uint64_t n)
{
    if (n < 8) {
        return 4;
    } else if (n < 33) {
        return 7;
    } else {
        return 10;
    }
}

static inline uint64_t label_compressed( const uint32_t n
									   , const uint32_t bits)
{
    if (1 == n) {
        return 1;
    }

    switch (bits) {
        case 10:
            if (0 == n) {
                return 0;
            }
            return ((n-1) << 2);
        case 4:
            if (0 == n) {
                return 3;
            }
            return (n << 1) | 1;
        case 7:
            if (0 == n) {
                return 2;
            }
            return ((n-1) << 2) | 2;
        default: return 0;
    }
}

static inline uint32_t label_decompress( const uint64_t label
                                       , const uint32_t bits )
{
    uint32_t n;
    switch (bits) {
        case 10:
            n = (label >> 2) & 0xffu;
            if (0 != n) {
                ++n;
            }
            return n;
        case 4:
            n = (label >> 1) & 0x7u;
            if (0 == n) {
                return 1;
            }
            if (1 == n) {
                return 0;
            }
            return n;
        case 7:
            n = (label >> 2) & 0x1fu;
            if (0 != n) {
                ++n;
            }
            return n;
        default: return 0;
    }
}

static inline uint64_t label_convertpov(uint64_t tar, uint64_t src)
{
    uint32_t tbits = label_bitsused_label(tar);
    uint32_t sbits = label_bitsused_label(src);
    if (tbits >= sbits) { return tar; }
    uint32_t tin = label_decompress(tar, tbits);
    return ((tar & (UINT64_MAX << tbits)) << (sbits - tbits)) | label_compressed(tin, sbits);
}

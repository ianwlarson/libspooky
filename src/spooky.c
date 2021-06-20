// Spooky Hash
// A 128-bit noncryptographic hash, for checksums and table lookup.
// Originally create by Bob Jenkins. Ported to C by Ian Larson

#include <memory.h>
#include <stdbool.h>
#include "spooky.h"

__attribute__((pure, always_inline))
static inline uint64_t
rd64(uint8_t const*const ptr)
{
    uint64_t o;
    __builtin_memcpy(&o, ptr, 8);
    return o;
}

__attribute__((pure, always_inline))
static inline uint32_t
rd32(uint8_t const*const ptr)
{
    uint32_t o;
    __builtin_memcpy(&o, ptr, 4);
    return o;
}

__attribute__((const, always_inline))
static inline uint64_t
rol64(uint64_t const x, unsigned const k)
{
    return (x << k) | (x >> (64 - k));
}

static void
spooky_short(void const*const message, size_t const length, uint64_t *hash1, uint64_t *hash2)
{
    size_t block_leftover = length % 32;

    uint64_t a = *hash1;
    uint64_t b = *hash1;
    uint64_t c = SC_CONST;
    uint64_t d = SC_CONST;

    size_t nbytes_processed = 0;

    if (length > 15) {

        size_t const blocks_of_32 = length / 32;

        nbytes_processed = blocks_of_32 * 32;

        if (((uintptr_t)message & 0x7) == 0) {
            // Aligned cases
            uint64_t const*datap = message;
            for (size_t i = 0; i < blocks_of_32; ++i) {

                c += datap[0];
                d += datap[1];
                c = rol64(c,50);  c += d;  a ^= c;
                d = rol64(d,52);  d += a;  b ^= d;
                a = rol64(a,30);  a += b;  c ^= a;
                b = rol64(b,41);  b += c;  d ^= b;
                c = rol64(c,54);  c += d;  a ^= c;
                d = rol64(d,48);  d += a;  b ^= d;
                a = rol64(a,38);  a += b;  c ^= a;
                b = rol64(b,37);  b += c;  d ^= b;
                c = rol64(c,62);  c += d;  a ^= c;
                d = rol64(d,34);  d += a;  b ^= d;
                a = rol64(a, 5);  a += b;  c ^= a;
                b = rol64(b,36);  b += c;  d ^= b;
                a += datap[2];
                b += datap[3];

                datap += 4;
            }

            //Handle the case of 16+ remaining bytes.
            if (block_leftover >= 16) {
                c += datap[0];
                d += datap[1];
                c = rol64(c,50);  c += d;  a ^= c;
                d = rol64(d,52);  d += a;  b ^= d;
                a = rol64(a,30);  a += b;  c ^= a;
                b = rol64(b,41);  b += c;  d ^= b;
                c = rol64(c,54);  c += d;  a ^= c;
                d = rol64(d,48);  d += a;  b ^= d;
                a = rol64(a,38);  a += b;  c ^= a;
                b = rol64(b,37);  b += c;  d ^= b;
                c = rol64(c,62);  c += d;  a ^= c;
                d = rol64(d,34);  d += a;  b ^= d;
                a = rol64(a, 5);  a += b;  c ^= a;
                b = rol64(b,36);  b += c;  d ^= b;

                nbytes_processed += 16;

                block_leftover -= 16;
            }

        } else {

            // Data is unaligned, use rd64 macro (on armv8 (64-bit) & x86_64
            // this will compile to a regular load.
            uint8_t const*datap = message;
            for (size_t i = 0; i < blocks_of_32; ++i) {

                c += rd64(datap);
                d += rd64(datap + 8);
                c = rol64(c,50);  c += d;  a ^= c;
                d = rol64(d,52);  d += a;  b ^= d;
                a = rol64(a,30);  a += b;  c ^= a;
                b = rol64(b,41);  b += c;  d ^= b;
                c = rol64(c,54);  c += d;  a ^= c;
                d = rol64(d,48);  d += a;  b ^= d;
                a = rol64(a,38);  a += b;  c ^= a;
                b = rol64(b,37);  b += c;  d ^= b;
                c = rol64(c,62);  c += d;  a ^= c;
                d = rol64(d,34);  d += a;  b ^= d;
                a = rol64(a, 5);  a += b;  c ^= a;
                b = rol64(b,36);  b += c;  d ^= b;
                a += rd64(datap + 16);
                b += rd64(datap + 24);

                datap += 32;
            }

            // More than 16 bytes remaining
            if (block_leftover >= 16) {

                c += rd64(datap);
                d += rd64(datap + 8);
                c = rol64(c,50);  c += d;  a ^= c;
                d = rol64(d,52);  d += a;  b ^= d;
                a = rol64(a,30);  a += b;  c ^= a;
                b = rol64(b,41);  b += c;  d ^= b;
                c = rol64(c,54);  c += d;  a ^= c;
                d = rol64(d,48);  d += a;  b ^= d;
                a = rol64(a,38);  a += b;  c ^= a;
                b = rol64(b,37);  b += c;  d ^= b;
                c = rol64(c,62);  c += d;  a ^= c;
                d = rol64(d,34);  d += a;  b ^= d;
                a = rol64(a, 5);  a += b;  c ^= a;
                b = rol64(b,36);  b += c;  d ^= b;

                nbytes_processed += 16;

                block_leftover -= 16;
            }

        }
    }

    // Handle the last 0..15 bytes, and and also add in the length
    d += ((uint64_t)length) << 56;

    uint8_t const*r = (uint8_t const*)message + nbytes_processed;
    switch (block_leftover)
    {
        case 15:
            d += ((uint64_t)r[14]) << 48;
        case 14:
            d += ((uint64_t)r[13]) << 40;
        case 13:
            d += ((uint64_t)r[12]) << 32;
        case 12:
            d += (uint64_t)rd32(r + 8);
            c += rd64(r);
            break;
        case 11:
            d += ((uint64_t)r[10]) << 16;
        case 10:
            d += ((uint64_t)r[9]) << 8;
        case 9:
            d += (uint64_t)r[8];
        case 8:
            c += rd64(r);
            break;
        case 7:
            c += ((uint64_t)r[6]) << 48;
        case 6:
            c += ((uint64_t)r[5]) << 40;
        case 5:
            c += ((uint64_t)r[4]) << 32;
        case 4:
            c += (uint64_t)rd32(r);
            break;
        case 3:
            c += ((uint64_t)r[2]) << 16;
        case 2:
            c += ((uint64_t)r[1]) << 8;
        case 1:
            c += (uint64_t)r[0];
            break;
        case 0:
            c += SC_CONST;
            d += SC_CONST;
        default:
            break;
    }

    d ^= c;  c = rol64(c,15);  d += c;
    a ^= d;  d = rol64(d,52);  a += d;
    b ^= a;  a = rol64(a,26);  b += a;
    c ^= b;  b = rol64(b,51);  c += b;
    d ^= c;  c = rol64(c,28);  d += c;
    a ^= d;  d = rol64(d, 9);  a += d;
    b ^= a;  a = rol64(a,47);  b += a;
    c ^= b;  b = rol64(b,54);  c += b;
    d ^= c;  c = rol64(c,32);  d += c;
    a ^= d;  d = rol64(d,25);  a += d;
    b ^= a;  a = rol64(a,63);  b += a;
    *hash1 = a;
    *hash2 = b;
}

void
spooky_hash128(void const*const message, size_t const length,
    uint64_t *const hash1, uint64_t *const hash2)
{
    if (length < SC_BUFSIZE)
    {
        spooky_short(message, length, hash1, hash2);
        return;
    }

    uint64_t const seed0 = *hash1;
    uint64_t const seed1 = *hash2;

    uint64_t h0 = seed0;
    uint64_t h1 = seed1;
    uint64_t h2 = SC_CONST;
    uint64_t h3 = seed0;
    uint64_t h4 = seed1;
    uint64_t h5 = SC_CONST;
    uint64_t h6 = seed0;
    uint64_t h7 = seed1;
    uint64_t h8 = SC_CONST;
    uint64_t h9 = seed0;
    uint64_t h10 = seed1;
    uint64_t h11 = SC_CONST;

    size_t const num_blocks = length / SC_BLOCKSIZE;
    size_t const nbytes_processed = num_blocks * SC_BLOCKSIZE;
    size_t const block_leftover = length - nbytes_processed;

    // Handle blocks
    if (((uintptr_t)message & 0x7) == 0) {

        uint64_t const*datap = message;
        for (size_t i = 0; i < num_blocks; ++i) {

            h0 += datap[0];    h2  ^= h10; h11 ^= h0;   h0  = rol64(h0,11);    h11 += h1;
            h1 += datap[1];    h3  ^= h11; h0  ^= h1;   h1  = rol64(h1,32);    h0  += h2;
            h2 += datap[2];    h4  ^= h0;  h1  ^= h2;   h2  = rol64(h2,43);    h1  += h3;
            h3 += datap[3];    h5  ^= h1;  h2  ^= h3;   h3  = rol64(h3,31);    h2  += h4;
            h4 += datap[4];    h6  ^= h2;  h3  ^= h4;   h4  = rol64(h4,17);    h3  += h5;
            h5 += datap[5];    h7  ^= h3;  h4  ^= h5;   h5  = rol64(h5,28);    h4  += h6;
            h6 += datap[6];    h8  ^= h4;  h5  ^= h6;   h6  = rol64(h6,39);    h5  += h7;
            h7 += datap[7];    h9  ^= h5;  h6  ^= h7;   h7  = rol64(h7,57);    h6  += h8;
            h8 += datap[8];    h10 ^= h6;  h7  ^= h8;   h8  = rol64(h8,55);    h7  += h9;
            h9 += datap[9];    h11 ^= h7;  h8  ^= h9;   h9  = rol64(h9,54);    h8  += h10;
            h10 += datap[10];  h0  ^= h8;  h9  ^= h10;  h10 = rol64(h10,22);   h9  += h11;
            h11 += datap[11];  h1  ^= h9;  h10 ^= h11;  h11 = rol64(h11,46);   h10 += h0;

            datap += SC_NUMVARS;
        }
    } else {

        uint8_t const*datap = message;
        for (size_t i = 0; i < num_blocks; ++i) {
            h0 +=  rd64(datap +  0);  h2  ^= h10; h11 ^= h0;   h0  = rol64(h0,11);    h11 += h1;
            h1 +=  rd64(datap +  8);  h3  ^= h11; h0  ^= h1;   h1  = rol64(h1,32);    h0  += h2;
            h2 +=  rd64(datap + 16);  h4  ^= h0;  h1  ^= h2;   h2  = rol64(h2,43);    h1  += h3;
            h3 +=  rd64(datap + 24);  h5  ^= h1;  h2  ^= h3;   h3  = rol64(h3,31);    h2  += h4;
            h4 +=  rd64(datap + 32);  h6  ^= h2;  h3  ^= h4;   h4  = rol64(h4,17);    h3  += h5;
            h5 +=  rd64(datap + 40);  h7  ^= h3;  h4  ^= h5;   h5  = rol64(h5,28);    h4  += h6;
            h6 +=  rd64(datap + 48);  h8  ^= h4;  h5  ^= h6;   h6  = rol64(h6,39);    h5  += h7;
            h7 +=  rd64(datap + 56);  h9  ^= h5;  h6  ^= h7;   h7  = rol64(h7,57);    h6  += h8;
            h8 +=  rd64(datap + 64);  h10 ^= h6;  h7  ^= h8;   h8  = rol64(h8,55);    h7  += h9;
            h9 +=  rd64(datap + 72);  h11 ^= h7;  h8  ^= h9;   h9  = rol64(h9,54);    h8  += h10;
            h10 += rd64(datap + 80);  h0  ^= h8;  h9  ^= h10;  h10 = rol64(h10,22);   h9  += h11;
            h11 += rd64(datap + 88);  h1  ^= h9;  h10 ^= h11;  h11 = rol64(h11,46);   h10 += h0;
            datap += SC_BLOCKSIZE;
        }
    }

    // Handle any leftover bytes that can't make a full block
    uint64_t last_block[SC_NUMVARS];
    __builtin_memcpy(last_block, (uint8_t const*)message + nbytes_processed, block_leftover);
    __builtin_memset(((uint8_t *)last_block) + block_leftover, 0, SC_BLOCKSIZE - block_leftover);
    ((uint8_t *)last_block)[SC_BLOCKSIZE-1] = block_leftover;

    h0  += last_block[0];
    h1  += last_block[1];
    h2  += last_block[2];
    h3  += last_block[3];
    h4  += last_block[4];
    h5  += last_block[5];
    h6  += last_block[6];
    h7  += last_block[7];
    h8  += last_block[8];
    h9  += last_block[9];
    h10 += last_block[10];
    h11 += last_block[11];

    for (int i = 0; i < 3; ++i) {
        h11+= h1;    h2 ^= h11;   h1 = rol64(h1,44);
        h0 += h2;    h3 ^= h0;    h2 = rol64(h2,15);
        h1 += h3;    h4 ^= h1;    h3 = rol64(h3,34);
        h2 += h4;    h5 ^= h2;    h4 = rol64(h4,21);
        h3 += h5;    h6 ^= h3;    h5 = rol64(h5,38);
        h4 += h6;    h7 ^= h4;    h6 = rol64(h6,33);
        h5 += h7;    h8 ^= h5;    h7 = rol64(h7,10);
        h6 += h8;    h9 ^= h6;    h8 = rol64(h8,13);
        h7 += h9;    h10^= h7;    h9 = rol64(h9,38);
        h8 += h10;   h11^= h8;    h10= rol64(h10,53);
        h9 += h11;   h0 ^= h9;    h11= rol64(h11,42);
        h10+= h0;    h1 ^= h10;   h0 = rol64(h0,54);
    }

    *hash1 = h0;
    *hash2 = h1;
}

// init spooky state
void
spooky_init(spooky_context_t *const context, uint64_t const seed0, uint64_t const seed1)
{
    context->m_length = 0;
    context->m_partial = 0;

    context->s0 = seed0;
    context->s1 = seed1;
    context->s2 = SC_CONST;
    context->s3 = seed0;
    context->s4 = seed1;
    context->s5 = SC_CONST;
    context->s6 = seed0;
    context->s7 = seed1;
    context->s8 = SC_CONST;
    context->s9 = seed0;
    context->s10 = seed1;
    context->s11 = SC_CONST;
}

void
spooky_update(spooky_context_t *const sc, void const*msg, size_t msglen)
{
    size_t current_datalen;
    bool const overflow1 = __builtin_add_overflow(sc->m_length, sc->m_partial, &current_datalen);
    if (!overflow1 && (current_datalen < SC_BUFSIZE)) {
        // The first addition didn't overflow, and we have less than SC_BUFSIZE bytes.
        // Check to see if the second addition overflows
        size_t next_datalen;
        bool const overflow2 = __builtin_add_overflow(current_datalen, msglen, &next_datalen);
        if (!overflow2 && (next_datalen < SC_BUFSIZE)) {
            __builtin_memcpy((unsigned char *)sc->m_unhashed + sc->m_partial, msg, msglen);
            sc->m_partial += msglen;
            return;
        }
    }

    // We've gone beyond a small buffer, we can operate on blocks now

    unsigned char const*lmsg = msg;

    uint64_t h0 = sc->s0;
    uint64_t h1 = sc->s1;
    uint64_t h2 = sc->s2;
    uint64_t h3 = sc->s3;
    uint64_t h4 = sc->s4;
    uint64_t h5 = sc->s5;
    uint64_t h6 = sc->s6;
    uint64_t h7 = sc->s7;
    uint64_t h8 = sc->s8;
    uint64_t h9 = sc->s9;
    uint64_t h10 = sc->s10;
    uint64_t h11 = sc->s11;

    bool mixed = false;
    // The first time the amount of data goes over SC_BUFSIZE, we can have more
    // than SC_BLOCKSIZE data in our partial buffer
    if (sc->m_partial >= SC_BLOCKSIZE) {
        uint64_t const* datap = sc->m_unhashed;
        h0 += datap[0];    h2  ^= h10; h11 ^= h0;   h0  = rol64(h0,11);    h11 += h1;
        h1 += datap[1];    h3  ^= h11; h0  ^= h1;   h1  = rol64(h1,32);    h0  += h2;
        h2 += datap[2];    h4  ^= h0;  h1  ^= h2;   h2  = rol64(h2,43);    h1  += h3;
        h3 += datap[3];    h5  ^= h1;  h2  ^= h3;   h3  = rol64(h3,31);    h2  += h4;
        h4 += datap[4];    h6  ^= h2;  h3  ^= h4;   h4  = rol64(h4,17);    h3  += h5;
        h5 += datap[5];    h7  ^= h3;  h4  ^= h5;   h5  = rol64(h5,28);    h4  += h6;
        h6 += datap[6];    h8  ^= h4;  h5  ^= h6;   h6  = rol64(h6,39);    h5  += h7;
        h7 += datap[7];    h9  ^= h5;  h6  ^= h7;   h7  = rol64(h7,57);    h6  += h8;
        h8 += datap[8];    h10 ^= h6;  h7  ^= h8;   h8  = rol64(h8,55);    h7  += h9;
        h9 += datap[9];    h11 ^= h7;  h8  ^= h9;   h9  = rol64(h9,54);    h8  += h10;
        h10 += datap[10];  h0  ^= h8;  h9  ^= h10;  h10 = rol64(h10,22);   h9  += h11;
        h11 += datap[11];  h1  ^= h9;  h10 ^= h11;  h11 = rol64(h11,46);   h10 += h0;

        sc->m_partial -= SC_BLOCKSIZE;
        sc->m_length += SC_BLOCKSIZE;
        if (sc->m_length < SC_BLOCKSIZE) {
            sc->overflowed = true;
        }

        __builtin_memcpy(sc->m_unhashed, (unsigned char *)sc->m_unhashed + SC_BLOCKSIZE, sc->m_partial);

        mixed = true;
    }

    // Empty the partial buffer ASAP so we can hash the data directly without
    // copying.
    if (sc->m_partial > 0) {
        size_t const fillamt = SC_BLOCKSIZE - sc->m_partial;
        if (msglen < fillamt) {
            // Not enough data to do a block
            __builtin_memcpy((unsigned char *)sc->m_unhashed + sc->m_partial, lmsg, msglen);
            sc->m_partial += msglen;

            if (mixed) {
                sc->s0 = h0;
                sc->s1 = h1;
                sc->s2 = h2;
                sc->s3 = h3;
                sc->s4 = h4;
                sc->s5 = h5;
                sc->s6 = h6;
                sc->s7 = h7;
                sc->s8 = h8;
                sc->s9 = h9;
                sc->s10 = h10;
                sc->s11 = h11;
            }
            return;
        } else {
            __builtin_memcpy((unsigned char *)sc->m_unhashed + sc->m_partial, lmsg, fillamt);

            uint64_t const* datap = sc->m_unhashed;
            h0 += datap[0];    h2  ^= h10; h11 ^= h0;   h0  = rol64(h0,11);    h11 += h1;
            h1 += datap[1];    h3  ^= h11; h0  ^= h1;   h1  = rol64(h1,32);    h0  += h2;
            h2 += datap[2];    h4  ^= h0;  h1  ^= h2;   h2  = rol64(h2,43);    h1  += h3;
            h3 += datap[3];    h5  ^= h1;  h2  ^= h3;   h3  = rol64(h3,31);    h2  += h4;
            h4 += datap[4];    h6  ^= h2;  h3  ^= h4;   h4  = rol64(h4,17);    h3  += h5;
            h5 += datap[5];    h7  ^= h3;  h4  ^= h5;   h5  = rol64(h5,28);    h4  += h6;
            h6 += datap[6];    h8  ^= h4;  h5  ^= h6;   h6  = rol64(h6,39);    h5  += h7;
            h7 += datap[7];    h9  ^= h5;  h6  ^= h7;   h7  = rol64(h7,57);    h6  += h8;
            h8 += datap[8];    h10 ^= h6;  h7  ^= h8;   h8  = rol64(h8,55);    h7  += h9;
            h9 += datap[9];    h11 ^= h7;  h8  ^= h9;   h9  = rol64(h9,54);    h8  += h10;
            h10 += datap[10];  h0  ^= h8;  h9  ^= h10;  h10 = rol64(h10,22);   h9  += h11;
            h11 += datap[11];  h1  ^= h9;  h10 ^= h11;  h11 = rol64(h11,46);   h10 += h0;

            sc->m_partial = 0;
            sc->m_length += SC_BLOCKSIZE;
            if (sc->m_length < SC_BLOCKSIZE) {
                sc->overflowed = true;
            }

            msglen -= fillamt;
            lmsg += fillamt;
        }
    }

    size_t const num_blocks = msglen / SC_BLOCKSIZE;
    size_t const nbytes_processed = num_blocks * SC_BLOCKSIZE;
    size_t const leftover = msglen - nbytes_processed;

    sc->m_length += nbytes_processed;
    if (sc->m_length < nbytes_processed) {
        sc->overflowed = true;
    }

    // Handle blocks
    if (((uintptr_t)lmsg & 0x7) == 0) {

        uint64_t const*datap = (void *)lmsg;
        for (size_t i = 0; i < num_blocks; ++i) {

            h0 += datap[0];    h2  ^= h10; h11 ^= h0;   h0  = rol64(h0,11);    h11 += h1;
            h1 += datap[1];    h3  ^= h11; h0  ^= h1;   h1  = rol64(h1,32);    h0  += h2;
            h2 += datap[2];    h4  ^= h0;  h1  ^= h2;   h2  = rol64(h2,43);    h1  += h3;
            h3 += datap[3];    h5  ^= h1;  h2  ^= h3;   h3  = rol64(h3,31);    h2  += h4;
            h4 += datap[4];    h6  ^= h2;  h3  ^= h4;   h4  = rol64(h4,17);    h3  += h5;
            h5 += datap[5];    h7  ^= h3;  h4  ^= h5;   h5  = rol64(h5,28);    h4  += h6;
            h6 += datap[6];    h8  ^= h4;  h5  ^= h6;   h6  = rol64(h6,39);    h5  += h7;
            h7 += datap[7];    h9  ^= h5;  h6  ^= h7;   h7  = rol64(h7,57);    h6  += h8;
            h8 += datap[8];    h10 ^= h6;  h7  ^= h8;   h8  = rol64(h8,55);    h7  += h9;
            h9 += datap[9];    h11 ^= h7;  h8  ^= h9;   h9  = rol64(h9,54);    h8  += h10;
            h10 += datap[10];  h0  ^= h8;  h9  ^= h10;  h10 = rol64(h10,22);   h9  += h11;
            h11 += datap[11];  h1  ^= h9;  h10 ^= h11;  h11 = rol64(h11,46);   h10 += h0;

            datap += SC_NUMVARS;
        }
    } else {

        uint8_t const*datap = lmsg;
        for (size_t i = 0; i < num_blocks; ++i) {
            h0 +=  rd64(datap +  0);  h2  ^= h10; h11 ^= h0;   h0  = rol64(h0,11);    h11 += h1;
            h1 +=  rd64(datap +  8);  h3  ^= h11; h0  ^= h1;   h1  = rol64(h1,32);    h0  += h2;
            h2 +=  rd64(datap + 16);  h4  ^= h0;  h1  ^= h2;   h2  = rol64(h2,43);    h1  += h3;
            h3 +=  rd64(datap + 24);  h5  ^= h1;  h2  ^= h3;   h3  = rol64(h3,31);    h2  += h4;
            h4 +=  rd64(datap + 32);  h6  ^= h2;  h3  ^= h4;   h4  = rol64(h4,17);    h3  += h5;
            h5 +=  rd64(datap + 40);  h7  ^= h3;  h4  ^= h5;   h5  = rol64(h5,28);    h4  += h6;
            h6 +=  rd64(datap + 48);  h8  ^= h4;  h5  ^= h6;   h6  = rol64(h6,39);    h5  += h7;
            h7 +=  rd64(datap + 56);  h9  ^= h5;  h6  ^= h7;   h7  = rol64(h7,57);    h6  += h8;
            h8 +=  rd64(datap + 64);  h10 ^= h6;  h7  ^= h8;   h8  = rol64(h8,55);    h7  += h9;
            h9 +=  rd64(datap + 72);  h11 ^= h7;  h8  ^= h9;   h9  = rol64(h9,54);    h8  += h10;
            h10 += rd64(datap + 80);  h0  ^= h8;  h9  ^= h10;  h10 = rol64(h10,22);   h9  += h11;
            h11 += rd64(datap + 88);  h1  ^= h9;  h10 ^= h11;  h11 = rol64(h11,46);   h10 += h0;
            datap += SC_BLOCKSIZE;
        }
    }

    // Stash any remainder to be hashed later
    if (leftover != 0) {
        __builtin_memcpy(sc->m_unhashed, lmsg + nbytes_processed, leftover);
        sc->m_partial = leftover;
    }

    // Copy the contents back in to the state
    sc->s0 = h0;
    sc->s1 = h1;
    sc->s2 = h2;
    sc->s3 = h3;
    sc->s4 = h4;
    sc->s5 = h5;
    sc->s6 = h6;
    sc->s7 = h7;
    sc->s8 = h8;
    sc->s9 = h9;
    sc->s10 = h10;
    sc->s11 = h11;
}

void
spooky_final(spooky_context_t const*const sc, uint64_t *hash0, uint64_t *hash1)
{
    size_t current_datalen;
    bool const overflow = __builtin_add_overflow(sc->m_length, sc->m_partial, &current_datalen);
    if (!sc->overflowed && (!overflow) && (current_datalen < SC_BUFSIZE)) {

        *hash0 = sc->s0;
        *hash1 = sc->s1;
        spooky_short(sc->m_unhashed, sc->m_partial, hash0, hash1);
        return;
    }

    // Make a local copy of the state, we cannot modify the internal state
    uint64_t h0 = sc->s0;
    uint64_t h1 = sc->s1;
    uint64_t h2 = sc->s2;
    uint64_t h3 = sc->s3;
    uint64_t h4 = sc->s4;
    uint64_t h5 = sc->s5;
    uint64_t h6 = sc->s6;
    uint64_t h7 = sc->s7;
    uint64_t h8 = sc->s8;
    uint64_t h9 = sc->s9;
    uint64_t h10 = sc->s10;
    uint64_t h11 = sc->s11;

    uint64_t last_block[SC_NUMVARS];

    size_t const leftover = sc->m_partial;
    __builtin_memcpy(last_block, sc->m_unhashed, leftover);
    __builtin_memset((uint8_t *)last_block + leftover, 0, SC_BLOCKSIZE - leftover);
    ((uint8_t *)last_block)[SC_BLOCKSIZE-1] = leftover;

    h0  += last_block[0];
    h1  += last_block[1];
    h2  += last_block[2];
    h3  += last_block[3];
    h4  += last_block[4];
    h5  += last_block[5];
    h6  += last_block[6];
    h7  += last_block[7];
    h8  += last_block[8];
    h9  += last_block[9];
    h10 += last_block[10];
    h11 += last_block[11];

    for (int i = 0; i < 3; ++i) {
        h11+= h1;    h2 ^= h11;   h1 = rol64(h1,44);
        h0 += h2;    h3 ^= h0;    h2 = rol64(h2,15);
        h1 += h3;    h4 ^= h1;    h3 = rol64(h3,34);
        h2 += h4;    h5 ^= h2;    h4 = rol64(h4,21);
        h3 += h5;    h6 ^= h3;    h5 = rol64(h5,38);
        h4 += h6;    h7 ^= h4;    h6 = rol64(h6,33);
        h5 += h7;    h8 ^= h5;    h7 = rol64(h7,10);
        h6 += h8;    h9 ^= h6;    h8 = rol64(h8,13);
        h7 += h9;    h10^= h7;    h9 = rol64(h9,38);
        h8 += h10;   h11^= h8;    h10= rol64(h10,53);
        h9 += h11;   h0 ^= h9;    h11= rol64(h11,42);
        h10+= h0;    h1 ^= h10;   h0 = rol64(h0,54);
    }

    *hash0 = h0;
    *hash1 = h1;
}


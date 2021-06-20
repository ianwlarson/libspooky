#pragma once
// Spooky Hash
// A 128-bit noncryptographic hash, for checksums and table lookup.
// Originally create by Bob Jenkins. Ported to C by Ian Larson

#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>
#include <inttypes.h>

#define SC_CONST UINT64_C(0xdeadbeefdeadbeef)
#define SC_NUMVARS 12
#define SC_BLOCKSIZE (SC_NUMVARS*8)
#define SC_BUFSIZE (2*SC_BLOCKSIZE)

void spooky_hash128(void const*p_msg, size_t p_len, uint64_t *ph1, uint64_t *ph2);

static inline uint64_t
spooky_hash64(void const*p_msg, size_t const p_len, uint64_t const p_seed)
{
    uint64_t hash1 = p_seed;
    uint64_t hash2 = p_seed;
    spooky_hash128(p_msg, p_len, &hash1, &hash2);
    return hash1;
}
static inline uint32_t
spooky_hash32(void const*p_msg, size_t const p_len, uint32_t const p_seed)
{
    return (uint32_t)spooky_hash64(p_msg, p_len, (uint64_t)p_seed);
}

struct spooky_context {
    size_t m_length;    // Amount of bytes that have been mixed
    size_t m_partial;   // Amount of unhashed data that is stored
    bool overflowed;
    uint64_t s0;
    uint64_t s1;
    uint64_t s2;
    uint64_t s3;
    uint64_t s4;
    uint64_t s5;
    uint64_t s6;
    uint64_t s7;
    uint64_t s8;
    uint64_t s9;
    uint64_t s10;
    uint64_t s11;
    // We need to store up to 2*SC_NUMVARS initially to correctly hash short
    // messages.
    uint64_t m_unhashed[2*SC_NUMVARS];
};

typedef struct spooky_context spooky_context_t;

void spooky_init(spooky_context_t *sc, uint64_t seed0, uint64_t seed1);
void spooky_update(spooky_context_t *sc, void const*msg, size_t msglen);
void spooky_final(spooky_context_t const*sc, uint64_t *hash0, uint64_t *hash1);

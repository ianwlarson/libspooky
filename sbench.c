
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>
#include <time.h>
#include <string.h>
#include <sys/mman.h>

#include "spooky.h"

static inline void
printhash(unsigned char *d)
{
    printf("    { ");
    for (int j = 0; j < 16; ++j) {
        printf("0x%02x, ", d[j]);
    }
    printf("},\n");
}

static inline uint32_t
xorshift32(uint32_t *const p_rng)
{
    uint32_t x = *p_rng;
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    *p_rng = x;
    return *p_rng;
}

static inline void
randfill(void *const p_dst, uint64_t const p_nbytes, uint32_t p_seed)
{
    if (p_seed == 0) {
        p_seed = 0xdeadbeef;
    }

    unsigned *l_dst = p_dst;
    int leftover = p_nbytes & (sizeof(unsigned) - 1);
    uint64_t const end = p_nbytes / sizeof(uint32_t);
    for (uint64_t i = 0; i < end; ++i) {
        l_dst[i] = xorshift32(&p_seed);
    }
    if (leftover > 0) {
        uint32_t const v = xorshift32(&p_seed);
        memcpy(&l_dst[end], &v, leftover);
    }
}

#define MAPSIZE UINT64_C(0x800000)
#define NLOOPS (55555)

int
main(int argc, char **argv)
{
    int offset = 0;
    if (argc > 1) {
        offset = strtol(argv[1], NULL, 0);
        if (offset < 0 || offset > 7) {
            printf("eek\n");
            exit(0);
        }
        if (offset == 0 && strcmp(argv[1], "0") != 0) {
            printf("bok\n");
            exit(0);
        }
    }
    unsigned *buff = mmap(0, MAPSIZE, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    unsigned rng = time(NULL) ^ getpid() * getpid();
    randfill(buff, MAPSIZE, rng);

    uint32_t carry_forward = 0xfaceb00cu;
    uint64_t difference = 0;
    struct timespec start,end;
    for (int i = 0; i < 100; ++i) {
        carry_forward = spooky_hash32((unsigned char *)buff + offset, MAPSIZE - offset, carry_forward);
    }

    for (int i = 0; i < NLOOPS; ++i) {
        clock_gettime(CLOCK_REALTIME, &start);
        carry_forward = spooky_hash32((unsigned char *)buff + offset, MAPSIZE - offset, carry_forward);
        clock_gettime(CLOCK_REALTIME, &end);
        difference += (end.tv_sec - start.tv_sec)*1000000000ull + (end.tv_nsec - start.tv_nsec);
    }

    uint64_t const total_data = (MAPSIZE - offset) * NLOOPS;
    printf("Total time %llu ns\n", difference);
    printf("Total bytes %" PRIu64 "\n", total_data);
    printf("Bytes per usec %f\n", 1.0*total_data / (difference / 1000.0));
    printf("Carry forward was %0x\n", carry_forward);

    return 0;
}

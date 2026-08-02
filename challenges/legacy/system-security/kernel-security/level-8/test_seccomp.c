/*
 * test_seccomp.c
 *
 *   1. vm build test_seccomp.c
 *   2. sudo insmod /challenge/debug.ko
 *   3. dmesg | tail -n 20
 *
 * 输出示例：
 * current_task offset = 0x15d00
 * machine code: 65 48 8b 04 25 00 5d 01 00
 */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/uaccess.h>

MODULE_LICENSE("GPL");

static void test_clear_seccomp(void)
{
    current->thread_info.flags &= ~(1 << TIF_SECCOMP);
}

static int __init offset_init(void)
{
    unsigned char *p = (unsigned char *)test_clear_seccomp;
    u32 offset;

    // 跳过 "65 48 8b 04 25" (mov rax, gs:[imm32])
    // 后面 4 字节就是被重定位后的 offset
    offset = *(u32 *)(p + 5);

    printk(KERN_INFO "current_task offset = 0x%x\n", offset);
    printk(KERN_INFO "machine code: %02x %02x %02x %02x %02x %02x %02x %02x %02x\n",
           p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7], p[8]);

    return 0;
}

static void __exit offset_exit(void) {}

module_init(offset_init);
module_exit(offset_exit);

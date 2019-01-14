#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Iram Lee");
MODULE_DESCRIPTION("A simple example Linux module.");
MODULE_VERSION("0.01");

// ========== SYS_CALL_TABLE ==========

// for x86_64
#if defined __x86_64__
    #define START_ADDRESS 0xffffffff81000000
    #define END_ADDRESS 0xffffffffa2000000

void **sys_call_table;

/**
 * Finds a system call table based on a heruistic.
 * Note that the heruistic is not ideal, so it might find a memory region that
 * looks like a system call table but is not actually a system call table, but
 * it seems to work all the time on my systems.
 *
 * @return system call table on success, NULL on failure.
 */
void **find_syscall_table(void)
{
    void **sctable;
    void *i = (void*) START_ADDRESS;

    while (i < END_ADDRESS) {
        sctable = (void **) i;

        // sadly only sys_close seems to be exported -- we can't check against more system calls
        if (sctable[__NR_close] == (void *) sys_close) {
            size_t j;
            // we expect there to be at least 300 system calls
            const unsigned int SYS_CALL_NUM = 300;
            // sanity check: no function pointer in the system call table should be NULL
            for (j = 0; j < SYS_CALL_NUM; j ++) {
                if (sctable[j] == NULL) {
                    // this is not a system call table
                    goto skip;
                }
            }
            return sctable;
        }
skip:
        ;
        i += sizeof(void *);
    }

    return NULL;
}
// ========== END SYS_CALL_TABLE ==========

static int __init lkm_example_init(void) {
  printk(KERN_INFO “Hello, World!\n”);
  /* Locate the system call table */
    sys_call_table = find_syscall_table();
    pr_info("Found sys_call_table at %p\n", sys_call_table);

  return 0;
}

static void __exit lkm_example_exit(void) {
  printk(KERN_INFO "Goodbye, World!\n");
}

module_init(lkm_example_init);
module_exit(lkm_example_exit);

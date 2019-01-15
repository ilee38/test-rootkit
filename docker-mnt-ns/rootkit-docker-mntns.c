#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/version.h>
#include <linux/list.h>
#include <linux/slab.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Iram Lee");
MODULE_DESCRIPTION("A simple example Linux module.");
MODULE_VERSION("0.01");

/*
 * Display the pointers (addresses) of each namespace inside the task (container)
*/
void show_ns_pointers(struct task_struct *tsk){
    //lock the parent task (i.e. containerd-shim)
    task_lock(tsk);
    struct nsproxy *parent_nsproxy = tsk->nsproxy;
    if(parent_nsproxy != NULL){
        pr_info("Parent mnt_ns address: %p\n", parent_nsproxy->mnt_ns);
        if(!list_empty(&tsk->children)){
       	    struct task_struct *child;
            pr_info("This task has children\n");
            list_for_each_entry(child, &tsk->children, children){
                //lock the child task (i.e. the actual container)
		task_lock(child);
                pr_info("PID of child: %u\n", child->pid);
		struct nsproxy *child_nsproxy = child->nsproxy;
		if(child_nsproxy != NULL){
		    pr_info("Child mnt_ns address BEFORE: %p\n", child_nsproxy->mnt_ns);
                    //Change the child's namespace address with the parent's ns address
		    child->nsproxy->mnt_ns = parent_nsproxy->mnt_ns;
      	            /* The next line is not necesary (function call) */
		    //switch_task_namespaces(child, parent_nsproxy);
		    pr_info("Child mnt_ns address AFTER: %p\n", child_nsproxy->mnt_ns);
		}
		task_unlock(child);
            }
        }
    }
    task_unlock(tsk);

    /*
    pr_info("Container namespace info: \n");
    pr_info("---------------------------\n");
    pr_info("mnt_ns address: %p\n", tsk->nsproxy->mnt_ns);
    pr_info("net_ns address: %p\n", tsk->nsproxy->net_ns);
    pr_info("pid_ns(for children) address: %p\n", tsk->nsproxy->pid_ns_for_children);
    pr_info("uts_ns address: %p\n", tsk->nsproxy->uts_ns);
    pr_info("ipc_ns address: %p\n", tsk->nsproxy->ipc_ns);
    */
}

/*
 * Access the namespaces of a Docker container. This is done through the
 * nsproxy structure of each container task (task_struct)
 * @return true on success, false on failure
*/
int access_namespaces(void){
    struct task_struct *task;
    char *tsk_name;
    for_each_process(task){
        char *buf_comm = kmalloc(sizeof(task->comm), GFP_KERNEL);
        if(!buf_comm){
            return 0;
        }
        tsk_name = get_task_comm(buf_comm, task);
	//The CFG_DOCKER_CONTAINER constant is defined in our config.h file
        if(strcmp(tsk_name, "docker-containe") == 0){
            pr_info("Found containerd \"%s\" with task PID: %d\n", tsk_name, task->pid);
            show_ns_pointers(task);
	}
        kfree(buf_comm);
    }
    return 1;
}

static int __init lkm_example_init(void) {
  printk(KERN_INFO "Hello, World!\n");
  /* Access the namespaces of a Docker container task */
  access_namespaces();
  return 0;
}

static void __exit lkm_example_exit(void) {
  printk(KERN_INFO "Goodbye, World!\n");
}

module_init(lkm_example_init);
module_exit(lkm_example_exit);

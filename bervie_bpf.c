#include <linux/sched.h>  // For task_struct
#include <linux/ptrace.h> // For struct pt_regs

struct triggered_event {
    u64 event_time;
    char syscall_name[16];
    int pid;
    int ppid;
    int uid;
    char process_path[256];  // Use a larger buffer for full path
    char parent_process_name[TASK_COMM_LEN];
};

BPF_PERF_OUTPUT(output);
BPF_HASH(is_block, u32, u32);

int syscall__execve(struct pt_regs *ctx, const char __user *pathname, char *const argv, char *const envp)
{
    struct triggered_event event = {};
    char called_syscall[16] = "exec";
    
    // Capture syscall name
    bpf_probe_read_kernel(&event.syscall_name, sizeof(event.syscall_name), called_syscall);

    // Capture process details BEFORE execve runs
    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct task_struct *parent_task = task->real_parent;

    // Get parent process name
    bpf_probe_read_kernel_str(event.parent_process_name, TASK_COMM_LEN, parent_task->comm);
    event.ppid = parent_task->pid;
    
    // Get the full pathname of the new process (target binary)
    bpf_probe_read_user_str(event.process_path, sizeof(event.process_path), pathname);

    // Submit event
    output.perf_submit(ctx, &event, sizeof(event));

    // Wait for Python to update `block_list`
    u32 key = 0;  // Fixed key, ensuring only one entry exists
    u32 *block = is_block.lookup(&key);
    
    if (block == 1) {
        bpf_trace_printk("Blocking execution of %s\n", event.process_path);
        return -1;  // Block execution
    }


    return 0;
}

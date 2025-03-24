#include <linux/sched.h>  // For task_struct

struct triggered_event {
    u64 event_time;
    char syscall_name[16];
    int pid;
    int ppid;
    int uid;
    char process_name[TASK_COMM_LEN];
    char parent_process_name[TASK_COMM_LEN];
    char target_file[128];

};



BPF_PERF_OUTPUT(output); 


static void enrich_data(void *ctx, struct triggered_event event)
{
    
    // What time is it?
    u64 now_time = bpf_ktime_get_ns();
    bpf_probe_read_kernel(&event.event_time, sizeof(now_time), &now_time);

    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    
    struct task_struct *task;
    struct task_struct *parent_task;

    // Get the current task_struct
    task = (struct task_struct *)bpf_get_current_task();

    // Get the parent task_struct 
    parent_task = task->real_parent;
    bpf_probe_read_kernel_str(&event.parent_process_name, TASK_COMM_LEN, parent_task->comm);

    int ppid = parent_task->pid;
    bpf_probe_read_kernel(&event.ppid, (sizeof(ppid)), &ppid);

    // Get the child's process name
    bpf_get_current_comm(&event.process_name, TASK_COMM_LEN);


    output.perf_submit(ctx, &event, sizeof(event)); 
}

int syscall__execve(struct pt_regs *ctx, const char __user *pathname, char *const argv, char *const envp)
{
    struct triggered_event event = {};
    char called_syscall[16] = "exec";   
    bpf_probe_read_kernel(&event.syscall_name, sizeof(event.syscall_name), called_syscall);
    bpf_probe_read_user_str(&event.target_file, sizeof(event.target_file), pathname);

    enrich_data(ctx, event);

    return 0;
}
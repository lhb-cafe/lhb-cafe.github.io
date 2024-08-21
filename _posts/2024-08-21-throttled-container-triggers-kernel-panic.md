---
title: "Container with limited CPU resource triggers system reboot"
categories:
  - Blog
tags:
  - kernel: locking
  - kernel: sched
---

## Background

**Issue description**
`khungtaskd` triggered kernel panic because some tasks were stuck in D state for too long. Multiple production environments encountered this issue in a few weeks. In the specific vmcore we received from customer, `khungtaskd` was triggered by task `systemd-journal`:

```
[12155580.980923] systemd-journal D 0 1553 1 0x00000080
[12155580.980926] Call Trace:
[12155580.980932] __schedule+0x292/0x880
[12155580.980936] ? single_open+0x5c/0xa0
[12155580.980937] schedule+0x32/0x80
[12155580.980938] schedule_preempt_disabled+0xa/0x10
[12155580.980940] __mutex_lock.isra.7+0x222/0x4c0
[12155580.980943] proc_cgroup_show+0x4a/0x290
[12155580.980946] proc_single_show+0x4a/0x80
[12155580.980947] seq_read+0xbd/0x3a0
[12155580.980951] __vfs_read+0x26/0x150
[12155580.980953] vfs_read+0x87/0x130
[12155580.980955] SyS_read+0x42/0xa0
[12155580.980958] do_syscall_64+0x74/0x160
[12155580.980960] entry_SYSCALL_64_after_hwframe+0x76/0xdb
```

**OS**
```
SLES12SP5
Kernel: 4.12.14-122.186-default
arch: x86_64
```

**SUSE Record**  
[bsc#1228347](https://bugzilla.suse.com/show_bug.cgi?id=1228347)

## Analysis


### 1. Task `systemd-journal`：blocked by `runc`

dmesg shows `systemd-journal` falls into D state waiting for a mutex:

```
[12155580.980940] __mutex_lock.isra.7+0x222/0x4c0
[12155580.980943] proc_cgroup_show+0x4a/0x290
```

The only mutex involved in `proc_cgroup_show` is `cgroup_mutex`:

```c
// kernel/cgroup/cgroup.c
int proc_cgroup_show(struct seq_file *m, struct pid_namespace *ns,
                     struct pid *pid, struct task_struct *tsk)
{
    // [...]
    mutex_lock(&cgroup_mutex);
    // [...]
}
```

Get the owner of `cgroup_mutex` from the vmcore:

```
crash> struct mutex.owner cgroup_mutex -x
  owner = {
    counter = 0xffff97e15bda86c1
  }
```

Notice that `task_struct` pointers are always at least `L1_CHACE_BYTES` aligned, so the last few bits in `mutex.owner` can be dropped (they are used to store additional information/flags of the mutex):

```c
// kernel/fork.c
void __init fork_init(void)
{
	// [...]
	// task_struct pointer is at least L1_CACHE_BYTES aligned
	int align = max_t(int, L1_CACHE_BYTES, ARCH_MIN_TASKALIGN);

	/* create a slab on which task_structs can be allocated */
	task_struct_cachep = kmem_cache_create("task_struct",
			arch_task_struct_size, align,
			SLAB_PANIC|SLAB_NOTRACK|SLAB_ACCOUNT, NULL);
	// [...]
}
```

Therefore, the owner is `0xffff97e15bda86c0`,  `runc` (pid: 14291)

### 2. Task `runc`: blocked on rwsem `cgroup_threadgroup_rwsem`


`runc` (pid: 14291) is itself also in D state waiting for a rwsem:

```
crash> bt -F 0xffff97e15bda86c0  
PID: 14291 TASK: ffff97e15bda86c0 CPU: 80 COMMAND: "runc"  
#0 [ffffb198b95b7c00] __schedule at ffffffffb37516a2  
ffffb198b95b7c08: [mm_struct] 0000000000000000  
ffffb198b95b7c18: [task_struct] [task_struct]  
ffffb198b95b7c28: ffff97e5c00232c0 ffffb198b95b7c88  
ffffb198b95b7c38: __schedule+658 [kmalloc-256]  
ffffb198b95b7c48: ffffb198b95b7c50 0000000000000000  
ffffb198b95b7c58: ffffffff00000004 [task_struct]  
ffffb198b95b7c68: cgroup_threadgroup_rwsem+72 ffffffff00000000  
ffffb198b95b7c78: cgroup_threadgroup_rwsem+96 ffffffff00000001  
ffffb198b95b7c88: ffffb198b95b7d18 schedule+50  
#1 [ffffb198b95b7c90] schedule at ffffffffb3751cc2  
ffffb198b95b7c98: [task_struct] rwsem_down_write_failed+480  
#2 [ffffb198b95b7ca0] rwsem_down_write_failed at ffffffffb3754a40  
ffffb198b95b7ca8: cgroup_threadgroup_rwsem+80 0000000000000000  
ffffb198b95b7cb8: 0000000000000000 0000000000000001  
ffffb198b95b7cc8: ffffb198b95b7cc0 cgroup_threadgroup_rwsem+80  
ffffb198b95b7cd8: cgroup_threadgroup_rwsem+80 [task_struct]  
ffffb198b95b7ce8: 0000000000000000 **cgroup_threadgroup_rwsem  
**ffffb198b95b7cf8: [kmalloc-2048] 0000000000000005  
ffffb198b95b7d08: 0000000000000001 [kmalloc-192]  
ffffb198b95b7d18: [kmalloc-192] call_rwsem_down_write_failed+19
[...]
```
As you might have guessed from the stack information, this task `runc` is waiting for `cgroup_threadgroup_rwsem`.

We could either verify this by analyzing the source code (like we have done above for the mutex) to find the input rwsem of the `down_write` call, or analyzing the ASM code with the `dis` util from crash to compute the offset of the rwsem (or its members) in the `rwsem_down_write_failed` stack frame. These procedures do not contain more interesting information so I will skip them for clarity.

Examine this `cgroup_threadgroup_rwsem`. It's reader-owned  (owner = 1), and its wait_list contains only one task `0xffffb198b95b7cd0`, that is, `runc` (no surprise, but we will see later that the useful information is no other tasks are blocking on this rwsem):

```
crash> struct percpu_rw_semaphore.rw_sem cgroup_threadgroup_rwsem  
rw_sem = {  
[...]  
wait_list = {  
next = 0xffffb198b95b7cd0,  
prev = 0xffffb198b95b7cd0  
},  
[...]  
owner = 0x1  
}  

crash> list -l rwsem_waiter.list -s rwsem_waiter.task 0xffffb198b95b7cd0  
ffffb198b95b7cd0  
task = 0xffff97e15bda86c0  
ffffffffb48b4630  
task = 0x0
```
In this v4.x kernel, rwsem does not store information about its reader-owners, so we can't get the owner directly as we did previously with the `cgroup_mutex`. In this case, finding the owner of a reader-owned rwsem can be tricky. We discuss this in the next section.


### 3. Task `runc:[2:INIT]`: owner of rwsem  `cgroup_threadgroup_rwsem`

One heuristic approach to find a reader-owner of a rwsem is to search every tasks' stacks and see if the rwsem is ever referenced. Most often the rwsem we are interested in is either global (such as in our case, `cgroup_threadgroup_rwsem`), or embedded inside another slab object (such as the infamous `mm_struct.mmap_sem`) .Thanks to the kernel's memory layout, these objects live in well-defined memory boundaries/pages, and we can use `bt -F` again with its really helpful feature of translating any global/slab objects from their addresses to their names.

( Another option would be to use `search -t`, but we would need to be more careful about its output because `search -t` searches not just the "active" stack frames, but the entire stack pages of all tasks, which may contain invalid/outdated data. Also, `search -t` in this case is often used with an additional `-m` option to specify a range of match addresses [^1])

[^1]: gcc does not always push the exact address of the object we are interested in on stack, but often with an offset like `[target_addr]+[offset]`(such as in this case, `cgroup_threadgroup_rwsem+72`). A mask allows us to search without knowing the exact value of offset.

```
crash> foreach bt -F | grep -a20 cgroup_threadgroup_rwsem
[...]
PID: 14309 TASK: ffff97dad1568840 CPU: 3 COMMAND: "runc:[2:INIT]"  
#0 [ffffb198bb80bc80] __schedule at ffffffffb37516a2  
ffffb198bb80bc88: [mm_struct] 0000000000000000  
ffffb198bb80bc98: [task_struct] [task_struct]  
ffffb198bb80bca8: ffff97e5bf4e32c0 ffffb198bb80bd08  
ffffb198bb80bcb8: __schedule+658 00000007f6fcd72d  
ffffb198bb80bcc8: ffffb198bb80bcd0 drain_stock+53  
ffffb198bb80bcd8: 0000000000000004 [task_struct]  
ffffb198bb80bce8: cgroup_threadgroup_rwsem+72 ffffb198bb80bd30  
ffffb198bb80bcf8: [task_struct] [kmalloc-128]  
ffffb198bb80bd08: ffffb198bb80bd80 schedule+50  
#1 [ffffb198bb80bd10] schedule at ffffffffb3751cc2  
ffffb198bb80bd18: [task_struct] rwsem_down_read_failed+255  
#2 [ffffb198bb80bd20] rwsem_down_read_failed at ffffffffb3754caf  
ffffb198bb80bd28: 0000000000000000 0000000000000001  
ffffb198bb80bd38: ffffb198bb80bd30 ffffb198b95b7cd8  
ffffb198bb80bd48: ffffb198b95b7cd8 0000000000000000  
ffffb198bb80bd58: ffff97e400000001 ffffb198bb80bec0  
ffffb198bb80bd68: cgroup_threadgroup_rwsem 00000000003d0f00  
ffffb198bb80bd78: 00000000c07db980 ffffb198bb80bec0  
ffffb198bb80bd88: call_rwsem_down_read_failed+20  
[...]
```

This `runc:[2:INIT]`'s backtrace looks like it's also waiting for `cgroup_threadgroup_rwsem`, but there are some crucial difference:

1. `runc:[2:INIT]` is in RU state. A waiter, on the contrary, would be in D state (unless it's under optimistic spinning, but READER optimistic spinning is not yet implemented in v4.12 kernel. Also, a spinning task would NOT call `schedule`):

```
crash> ps ffff97dad1568840
   PID    PPID  CPU       TASK        ST  %MEM     VSZ    RSS  COMM
  14309  14291   3  ffff97dad1568840  RU   0.0 1244868   3476  runc:[2:INIT]
```

2. We just confirmed in the previous section, that the wait_list of `cgroup_threadgroup_rwsem` contains no other tasks.

3. In additional, every waiter has a `struct rwsem_waiter` declared on stack. we can check the value of `rwsem_waiter.task` on its stack frame to determine if this task is still waiting. Refer to <a id="back-rwsem_waiter-analysis"> [appendix](#appendix-1)</a> for more details.

Therefore, we can conclude that `runc:[2:INIT]` must have already acquired `cgroup_threadgroup_rwsem`, but it is not scheduled to run on CPU yet, so its backtrace still looks like a waiter.

We discuss why `runc:[2:INIT]` does not run despite being in RU state in the next section.

### 4. `runc:[2:INIT]` starving on a throttled runqueue

`runc:[2:INIT]` has not run for 134 seconds (02:14). This explains why it's blocking the other two tasks for so long and even triggers a kernel panic (this host has the default `khungtaskd` threshold of 120 seconds).

```
crash> ps -m ffff97dad1568840  
[ 0 00:02:14.088] [RU] PID: 14309 TASK: ffff97dad1568840 CPU: 3 COMMAND: "runc:[2:INIT]"
```

In fact, some other RU tasks also have similar starvation issues:

```
crash> foreach RU ps -m | grep -v swapper | tail  
[ 0 00:00:12.109] [RU] PID: 45526 TASK: ffff97e02fb24780 CPU: 19 COMMAND: "pool-2-thread-3"  
[ 0 00:00:46.808] [RU] PID: 45529 TASK: ffff97df8a314880 CPU: 25 COMMAND: "pool-2-thread-6"  
[ 0 00:02:14.007] [RU] PID: 43779 TASK: ffff97dee178ccc0 CPU: 16 COMMAND: "C2 CompilerThre"  
[ 0 00:02:14.007] [RU] PID: 50485 TASK: ffff97e46b2c4800 CPU: 3 COMMAND: "csh"  
[ 0 00:02:14.010] [RU] PID: 45524 TASK: ffff97df0b588e00 CPU: 14 COMMAND: "pool-2-thread-1"  
[ 0 00:02:14.010] [RU] PID: 45525 TASK: ffff97e174624ec0 CPU: 24 COMMAND: "pool-2-thread-2"  
[ 0 00:02:14.007] [RU] PID: 45534 TASK: ffff97de98b3ca40 CPU: 15 COMMAND: "pool-2-thread-1"  
[ 0 00:02:14.007] [RU] PID: 43780 TASK: ffff97df17abd000 CPU: 10 COMMAND: "C1 CompilerThre"  
[ 0 00:02:14.088] [RU] PID: 14309 TASK: ffff97dad1568840 CPU: 3 COMMAND: "runc:[2:INIT]"  
[ 0 00:02:14.105] [RU] PID: 43754 TASK: ffff97e4f7274d80 CPU: 24 COMMAND: "VM Thread"
```

Examine their CFS runqueues. Turns out these tasks are all coming from task group `pod427b33b5-c993-41f1-b3f7-c2bbebfee969`, whose cfs_rq's are throttled:

（The host has 128 CPUs. We only show CPU 3 and CPU 24 here to illustrate the symptom）
```
crash> runq -g -c3
CPU 3
  CURRENT: PID: 0      TASK: ffff9768dab103c0  COMMAND: "swapper/3"
  ROOT_TASK_GROUP: ffffffffb4853480  RT_RQ: ffff97e5bf4e3500
     [no tasks queued]
  ROOT_TASK_GROUP: ffffffffb4853480  CFS_RQ: ffff97e5bf4e3340
     TASK_GROUP: ffff986595f19900  CFS_RQ: ffff97e5aea12a00  <kubepods>
        TASK_GROUP: ffff9865728d1340  CFS_RQ: ffff97de6b10e400  <pod427b33b5-c993-41f1-b3f7-c2bbebfee969> (THROTTLED)
           TASK_GROUP: ffff97e59a147900  CFS_RQ: ffff97e02f8b8800  <0af400083ce3c4cfb294f6c295068897f074837611ea528d79a80fcc0361fa29> (THROTTLED)
              [120] PID: 14309  TASK: ffff97dad1568840  COMMAND: "runc:[2:INIT]"
              [120] PID: 50485  TASK: ffff97e46b2c4800  COMMAND: "csh"
crash> runq -g -c24
CPU 24
  CURRENT: PID: 0      TASK: ffff9768dabb0900  COMMAND: "swapper/24"
  ROOT_TASK_GROUP: ffffffffb4853480  RT_RQ: ffff97e5bfa23500
     [no tasks queued]
  ROOT_TASK_GROUP: ffffffffb4853480  CFS_RQ: ffff97e5bfa23340
     TASK_GROUP: ffff986595f19900  CFS_RQ: ffff9768d7fcf000  <kubepods>
        TASK_GROUP: ffff9865728d1340  CFS_RQ: ffff97e4963e5200  <pod427b33b5-c993-41f1-b3f7-c2bbebfee969> (THROTTLED)
           TASK_GROUP: ffff97e59a147900  CFS_RQ: ffff97e4cbe9a200  <0af400083ce3c4cfb294f6c295068897f074837611ea528d79a80fcc0361fa29> (THROTTLED)
              [120] PID: 43754  TASK: ffff97e4f7274d80  COMMAND: "VM Thread"
              [120] PID: 45525  TASK: ffff97e174624ec0  COMMAND: "pool-2-thread-2"
```

It's reasonable to think that a throttled a cfs_rq will not get picked to run on CPU, but is it normal for a cfs_rq to be throttled for ~134 seconds?

### 5. Throttled cfs_rq receives unfair (LIFO) runtime distribution

For each CPU-limited task group, the kernel registers an hrtimer callback function to periodically update its runtime quota. If there is enough quota, the callback function also distributes these quota to all throttled cfs_rqs (manged in the list `cfs_bandwidth->throttled_cfs_rq`) and unthrottle them. However, if there is not enough quota to distribute, only the head parts of the list receive runtime and unthrottle, those in the tail remain throttled.

```c
// kernel/sched/fair.c
static u64 distribute_cfs_runtime(struct cfs_bandwidth *cfs_b,
                u64 remaining, u64 expires)
{
        struct cfs_rq *cfs_rq;
        u64 runtime;
        u64 starting_runtime = remaining;

        // [...]
        // traverse throttled_cfs_rq for the throttled cfs_rq
        list_for_each_entry_rcu(cfs_rq, &cfs_b->throttled_cfs_rq,
                                throttled_list) {
                // [...]
                // [HL] runtime to distribute and deduct from task_group's remaining
                runtime = -cfs_rq->runtime_remaining + 1;
                if (runtime > remaining)
                        runtime = remaining;
                remaining -= runtime;

                // [...]
                // [HL] now cfs_rq->runtime_remaining = 1 and unthrottle the cfs_rq
                cfs_rq->runtime_remaining += runtime;
                // [...]
                if (cfs_rq->runtime_remaining > 0)
                        unthrottle_cfs_rq(cfs_rq);

                // [...]
                // [HL] stop if depleted. the rest of cfs_rq remain throttled
                if (!remaining)
                        break;
        }
        // [...]
}
```

On the other side, when a cfs_rq become throttled, it is placed on the **head** of the `throttled_cfs_rq` list

```c
// kernel/sched/fair.c
static void throttle_cfs_rq(struct cfs_rq *cfs_rq)
{
        // [...]
        struct cfs_bandwidth *cfs_b = tg_cfs_bandwidth(cfs_rq->tg);

        // [...]
        // [HL]
        // initial design calls list_add_tail_rcu to place cfs_rq to the tail
        // this patch changed the behavior:
        // c06f04c70489 ("sched: Fix potential near-infinite distribute_cfs_runtime() loop")
        // [/HL]
        /*
         * Add to the _head_ of the list, so that an already-started
         * distribute_cfs_runtime will not see us
         */
        list_add_rcu(&cfs_rq->throttled_list, &cfs_b->throttled_cfs_rq);
        // [...]
}
```

Meaning, the list `throttled_cfs_rq` is LIFO.

In the extreme case where `distribute_cfs_runtime` don't get enough runtime quota to unthrottle all of its cfs_rq in every period, those cfs_rq unfortunately stuck on the tail of the list will continuously get "preempted" and starve.

The exact runtime a cfs_rq receive from `distribute_cfs_runtime` is equal to the `delta_exec` parameter passed into `__account_cfs_rq_runtime` call, which is calculated as the call time difference between two consecutive `update_curr` calls on that cfs_rq:

```c
// kernel/sched/fair.c
static void update_curr(struct cfs_rq *cfs_rq)
{
        // [...]
        u64 now = rq_clock_task(rq_of(cfs_rq));
        u64 delta_exec;
        // [...]
        delta_exec = now - curr->exec_start;
        // [...]
        curr->exec_start = now;
        // [...]
        account_cfs_rq_runtime(cfs_rq, delta_exec);
}  

// kernel/sched/fair.c
static void __account_cfs_rq_runtime(struct cfs_rq *cfs_rq, u64 delta_exec)
{       
        // [...]
        cfs_rq->runtime_remaining -= delta_exec;
        // [HL]
        // This is the runtime_remaining (negative value) of a throttled cfs_rq
        // Also runtime_remaining = 1 after unthrottle (see distribute_cfs_runtime)
        // So throttled runtime_remaining = 1 - delta_exec
        // Runtime to be distributed in the next distribute_cfs_runtime call:
        //     -(1 - delta_exec) + 1 == delta_exec
        // [/HL]
        // [...]
}
```

`delta_exec` is different in each call, but we can roughly get an estimation by looking at the CFS sysctl tunables and the actual CPU load at that moment. Normally this will be the timeslice a task get to run on CPU before preemption [^2], which is usually in milliseconds. Though we will not know the exact value, we pick a value of `3ms` just to showcase the issue.

[^2]: `update_curr` is called from many places, but the most frequent call here should be coming from context switches, especially considering that nothing much is happening to these cfs_rq's.

`runc:[2:INIT]`'s task group has a quota of 40000000ns, or 40ms, for each 100ms period:

```
crash> struct task_struct 0xffff97dad1568840
  sched_task_group =  0xffff97e59a147900,
    css = {
      cgroup = 0xffff97e5bcf3e000,
    [...]
    cfs_bandwidth = {
      period = 0x5f5e100,         period = 100000000,
      quota = 0x2625a00,          quota =   40000000,
      runtime = 0x0,
```

If we assume each cfs_rq in `throttled_cfs_rq` receives on average 3ms runtime from `distribute_cfs_runtime`, this full quota of 40ms is only able to feed about 14 cfs_rq from the list head, while the cfs_rq of `runc:[2:INIT]` is placed on the 21'st position in the list:

```
crash> p &((struct task_group*)0xffff97e59a147900)->cfs_bandwidth.throttled_cfs_rq
$1 = (struct list_head *) 0xffff97e59a147b78

crash> list -H 0xffff97e59a147b78 -o cfs_rq.throttled_list | awk '{print NR, $0}' | grep ffff97e02f8b8800
21 ffff97e02f8b8800
```
`runc:[2:INIT]`'s cfs_rq is on the list tail and starved. That's why it doesn't get to run for > 2 minutes.

## Root Cause

When a task group has CPU bandwith control enabled and multiple cfs_rq are throttled. The CFS bandwith control in this  kernel (v4.12) handles throttled cfs_rq with a LIFO list, potentially starving some cfs_rq on the tail part of the list. 

In this issue reported, the task group is a container `pod427b33b5-c993-41f1-b3f7-c2bbebfee969`:
- The starving task `runc:[2:INIT]` owns a rwsem, but never gets a chance to release it (cannot run for ~134 second).
- Task `runc` is a writer-waiter blocking on that rwsem. It in turn owns a mutex, blocking another task `systemd-journal`
- Task `systemd-journal` is blocked in D state for more than 120 seconds, triggering `khuntaskd` to raise a kernel panic.

## Solution<a id="solution"></a>

1. <a id="solution-1"></a>Increase the cgroup tunables cpu.cfs_quota_us and cpu.cfs_period_us proportionally, so in each period the task group gets more quota to unthrottle all cfs_rq. The trade-off is higher scheduling latency.
2. <a id="solution-2"></a>Bind the task group to fewer CPUs, so there will be fewer cfs_rq to unthrottle.
3. <a id="solution-3"></a>Upgrade the kernel (upgrade OS to SLES15.x). The LIFO throttling is removed since kernel v5.8. Refer to [appendix](#appendix-2) for the relevant patch history made by the cgroup maintainer.


## Appendix: Analyzing `rwsem_waiter`<a id="appendix-1"></a> 
[Original Text↩︎](#back-rwsem_waiter-analysis)

When a task is waiting for a rwsem, it declares a `struct rwsem_waiter` on its kernel stack, where the `rwsem_waiter.task` member points to itself. When the rwsem is granted to the task, this `rwsem_waiter.task` member will be set to NULL.

```c
// kernel/locking/rwsem-xadd.c
static inline struct rw_semaphore __sched *
__rwsem_down_read_failed_common(struct rw_semaphore *sem, int state)
{
        // [...]
        struct rwsem_waiter waiter;
        DEFINE_WAKE_Q(wake_q);

        waiter.task = current;
        waiter.type = RWSEM_WAITING_FOR_READ;
        // [...]
        list_add_tail(&waiter.list, &sem->wait_list);

        // [...]
        // [HL] wait for the rwsem
        while (true) {
                set_current_state(state);
                // [HL] waiter == null means the rwsem is already granted to us
                if (!waiter.task)
                        break;
                // [...]
                schedule();
        }
        // [...]
}

// kernel/locking/rwsem-xadd.c
// [HL] called by rwsem owner when releasing it
static void __rwsem_mark_wake(struct rw_semaphore *sem,
                              enum rwsem_wake_type wake_type,
                              struct wake_q_head *wake_q)
{
		struct rwsem_waiter *waiter, *tmp;
        // [...]
        list_for_each_entry_safe(waiter, tmp, &sem->wait_list, list) {
                // [...]
                // [HL] this loop only grant to consecutive reader-waiters
                if (waiter->type == RWSEM_WAITING_FOR_WRITE)
                        break;
				// [HL] reaching this line means rwsem is granted to waiter.tsk
				// [...]

				// [HL] remove waiter from rwsem->wait_list
                list_del(&waiter->list);

                // [...]
                // [HL] waiter.task set to null
                smp_store_release(&waiter->task, NULL);
                // [...]
        }
        // [...]
}
```

Therefore, the task already owns the rwsem if the the `rwsem_waiter.task` member on its `rwsem_down_read_failed` stack frame is NULL:

(Again, we can find its exact offset in the stack frame from disassembly, but we will skip that because it's quite clear looking directly at its `bt -F` output.)
```
crash> foreach bt -F | grep -a20 cgroup_threadgroup_rwsem
[...]
#2 [ffffb198bb80bd20] rwsem_down_read_failed at ffffffffb3754caf  
ffffb198bb80bd28: 0000000000000000 0000000000000001  
ffffb198bb80bd38: ffffb198bb80bd30 ffffb198b95b7cd8  <====== rwsem_waiter.list
ffffb198bb80bd48: ffffb198b95b7cd8 0000000000000000  <====== rwsem_waiter.task == NULL
ffffb198bb80bd58: ffff97e400000001 ffffb198bb80bec0  <====== rwsem_waiter.type == 00000001, i.e., RWSEM_WAITING_FOR_READ
ffffb198bb80bd68: cgroup_threadgroup_rwsem 00000000003d0f00  
ffffb198bb80bd78: 00000000c07db980 ffffb198bb80bec0  
ffffb198bb80bd88: call_rwsem_down_read_failed+20  
[...]
```

, where
```c
enum rwsem_waiter_type {
        RWSEM_WAITING_FOR_WRITE,
        RWSEM_WAITING_FOR_READ
};

struct rwsem_waiter {
        struct list_head list;
        struct task_struct *task;
        enum rwsem_waiter_type type;
};
```

## Appendix: Maintainer's Note on Patch History<a id="appendix-2"></a> 
[Original Text↩︎](#solution)

**[SUSE bsc#1190807 comment#63](https://bugzilla.suse.com/show_bug.cgi?id=1190807#c63):**

Michal Koutný 2021-10-01 16:41:54 UTC

```
History of LIFOness in CPU throttling

(Initially throttled list was FIFO)

c06f04c70489 ("sched: Fix potential near-infinite distribute_cfs_runtime() loop") v3.17-rc1\~134^2\~26
- the freshly unthrotlled cfs_rq could return back while distribute_cfs_runtime
  is still running and making an infinite loop, therefore not add to tail but
  head
- this deliberately introduced a race that allows (limited) exceeding of quota

baa9be4ffb55 ("sched/fair: Fix throttle_list starvation with low CFS quota") v4.19\~11^2\~1
- the original reasoning of this patch is very similar to our problem
- the upstream discussion says it's easy to reproduce with any CPU consumers
  [1]
- the fix made the list sometimes used as FIFO and sometimes as LIFO
  - that's likely why SLE15-SP3 looked better but didn't prevent the starvation
    completely

26a8b12747c9 ("sched/fair: Fix race between runtime distribution and assignment") v5.7-rc1\~5^2\~6
- this fixes the race with proper locking, no quota excesses

e98fa02c4f2e ("sched/fair: Eliminate bandwidth race between throttling and distribution") v5.8-rc1\~176^2\~37
- this removes LIFO for good -> the current kernel (e.g. TW) should be fair
  even on multiple CPUs
```

## Footnotes

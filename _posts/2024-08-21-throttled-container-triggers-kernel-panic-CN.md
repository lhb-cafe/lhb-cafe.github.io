---
title:  "容器CPU资源受限引发的血案"
categories:
  - Blog
tags:
  - kernel: locking
  - kernel: sched
hidden = true
---

## 背景

**问题描述**
客户有多个局点接连出现 khungtaskd 检测到有进程处于 D 状态时间过长，触发系统重启。dmesg 打印的进程信息如下：

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
SLES12SP5
Kernel: 4.12.14-122.186-default
arch: x86_64

**SUSE Record**
[bsc#1228347](https://bugzilla.suse.com/show_bug.cgi?id=1228347)

## 分析


### 1. systemd-journal 进程:  被 runc 阻塞

根据 dmesg 打印的进程堆栈信息，systemd-journal 进程在等 mutex 时进入 D 状态：

```
[12155580.980940] __mutex_lock.isra.7+0x222/0x4c0
[12155580.980943] proc_cgroup_show+0x4a/0x290
```

分析 proc_cgroup_show 代码，此时尝试获取的是 cgroup_mutex：

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

cgroup_mutex 是全局变量，vmcore 中直接查看其当前 owner：

```
crash> struct mutex.owner cgroup_mutex -x
  owner = {
    counter = 0xffff97e15bda86c1
  }
```

mutex.owner 中的最后几位被用于储存一些用于优化性能的标记位，此时 owner 应该是对齐后的 `0xffff97e15bda86c0`。参考 task_struct 对应的 slab 初始化时设置的对齐参数：

```c
// kernel/fork.c
void __init fork_init(void)
{
	// [...]
	// task_struct 指针至少是 L1_CACHE_BYTES 对齐
	int align = max_t(int, L1_CACHE_BYTES, ARCH_MIN_TASKALIGN);

	/* create a slab on which task_structs can be allocated */
	task_struct_cachep = kmem_cache_create("task_struct",
			arch_task_struct_size, align,
			SLAB_PANIC|SLAB_NOTRACK|SLAB_ACCOUNT, NULL);
	// [...]
}
```

小结：systemd-journal  被 `0xffff97e15bda86c0` 进程，即 runc (pid: 14291) 阻塞。

### 2. runc进程：阻塞在读写锁 cgroup_threadgroup_rwsem


runc (pid: 14291) 也阻塞在 D 状态，从其堆栈来看，是在等一个 rwsem:

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
通过堆栈信息可以推测等待的是 cgroup_threadgroup_rwsem（可以像上面分析 mutex 一样通过堆栈上下文结合代码分析，也可以用 dis 命令读汇编码确认 rwsem 在 rwsem_down_write_failed 堆栈中的偏移量，这里不再赘述)。

检查这个 cgroup_threadgroup_rwsem，为读者持锁 (owner = 1) ，且当前等待队列只有 `ffff97e15bda86c0` (即本 runc 进程) 一个进程：

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

小结：runc 进程阻塞在读写锁 cgroup_threadgroup_rwsem 上。在当前 kernel 版本，读者持锁时 rwsem 结构体中没有记录持有者的信息，因此不能像前面 cgroup_mutex 一样直接在 rwsem 结构体中找到持有者。

### 3. cgroup_threadgroup_rwsem 持有者: runc:[2:INIT] 进程

当一个进程持锁时，我们猜测它的堆栈中某处会引用到这把锁，所以找持锁进程的第一步往往是在其他进程的堆栈中搜索这把锁。这里有个小技巧，一般我们关心的锁要么是全局锁（比如本案例中的 cgroup_threadgroup_rwsem），要么是某个 slab 对象结构体中的成员（比如著名的大锁 mm_struct.mmap_sem）。全局变量和 slab 对象在内核地址空间中都是很容易确定其边界的，因此 crash 工具的 `bt -F` 提供了自动检测堆栈里的全局变量和 slab 对象的功能：

（另一个搜索堆栈的方法是 `search -t`，但要注意的是 `search -t` 搜索的不仅仅是 “有效” 堆栈，而是整个 stack page，所以可能包含一部分无效/过时信息。另外，在这个用例中，往往还需要额外计算并通过 `-m` 参数传入一个内存地址掩码，以实现地址段的搜索 [^1]。）

[^1]: 我们要找的变量往往会以 `[变量地址]+[某偏移量]`的形式入栈，比如本案例中的 `cgroup_threadgroup_rwsem+72`。通过传入内存地址掩码，我们可以在不提前得知偏移量的前提下，搜索一个模糊的范围。

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

这个 runc:[2:INIT] 进程的堆栈也是在 rwsem_down_read_failed 上，但同时要注意到
1. 该进程是 R 状态，并不像其他等锁的进程一样被阻塞在 D 状态：

```
crash> ps ffff97dad1568840
   PID    PPID  CPU       TASK        ST  %MEM     VSZ    RSS  COMM
  14309  14291   3  ffff97dad1568840  RU   0.0 1244868   3476  runc:[2:INIT]
```

2. 我们前面已经确认过，cgroup_threadgroup_rwsem 的等待队列里只有一个 runc（pid: 14291) 进程，即这个 runc:[2:INIT] 进程不在等待队列里。
3. <a id="back-rwsem_waiter-analysis"></a> 还可以通过堆栈中的 rwsem_waiter.task 是否为 null 来判断进程是否获取到 rwsem，分析较长，请参考[附录](#appendix-1)。

小结：唯一的可能性就是 runc:[2:INIT ]进程已经获得了 rwsem，但被唤醒后还没有得到调度，因此当前堆栈还停留在等锁时的状态。

### 4. runc:[2:INIT] 进程饿死在 throttled CFS 队列上

runc:[2:INIT]（pid: 14309) 上一次被调度到是在134秒 (02:14) 前：

```
crash> ps -m ffff97dad1568840  
[ 0 00:02:14.088] [RU] PID: 14309 TASK: ffff97dad1568840 CPU: 3 COMMAND: "runc:[2:INIT]"
```

查看系统其他 RU 进程的调度时间，发现也有长时间得不到调度的问题：

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

检查CFS队列状态，这些进程都来自进程组 `pod427b33b5-c993-41f1-b3f7-c2bbebfee969` ，且进程组的 CFS 队列处于throttled状态：

（CPU较多，这里只展示 CPU3 和 CPU24 上的队列）
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


### 5. 多个 throttled CFS 队列间不能保证公平分配 CPU 配额

当一个进程组配置了 CPU 带宽限制时，内核通过定时器周期性地更新进程组的 CPU 配额 （cfs_bandwidth->runtime），并遍历处于 throttled 状态的 CFS 队列（由 cfs_bandwidth->throttled_cfs_rq 链表管理），在配额足够的前提下，为这些队列分配配额（ cfs_rq->runtime_remaining）并解除它们的 throttled 状态。然而，如果进程组的配额不够分配，则会按照遍历顺序优先分配给 throttled_cfs_rq 链表头部的队列，链表尾部的队列因为得不到配额而继续处于 throttled 状态。

```c
// kernel/sched/fair.c
static u64 distribute_cfs_runtime(struct cfs_bandwidth *cfs_b,
                u64 remaining, u64 expires)
{
        struct cfs_rq *cfs_rq;
        u64 runtime;
        u64 starting_runtime = remaining;

        // [...]
        // 遍历进程组处于 throttled 状态的 cfs_rq
        list_for_each_entry_rcu(cfs_rq, &cfs_b->throttled_cfs_rq,
                                throttled_list) {
                // [...]
                // 给 cfs_rq 的配额，并从进程组 remaining 配额中扣除
                runtime = -cfs_rq->runtime_remaining + 1;
                if (runtime > remaining)
                        runtime = remaining;
                remaining -= runtime;

                // [...]
                // 将配额分配给 cfs_rq
                cfs_rq->runtime_remaining += runtime;
                // [...]
                // 解除 cfs_rq throttled 状态
                if (cfs_rq->runtime_remaining > 0)
                        unthrottle_cfs_rq(cfs_rq);

                // [...]
                // 如果进程组 remaining 配额耗尽，则终止遍历，链表尾部的 cfs_rq 将继续处于 throttled 状态
                if (!remaining)
                        break;
        }
        // [...]
}
```

再看 CFS 队列配额耗尽，申请配额又失败的情况下，队列进入 throttled 状态，并放入 throttled_cfs_rq 链表的**头部**

```c
// kernel/sched/fair.c
static void throttle_cfs_rq(struct cfs_rq *cfs_rq)
{
        // [...]
        struct cfs_bandwidth *cfs_b = tg_cfs_bandwidth(cfs_rq->tg);

        // [...]
        // 最早的版本是调用 list_add_tail_rcu 放入链表尾部
        // 在这个 patch 中改为放入头部：
        // c06f04c70489 ("sched: Fix potential near-infinite distribute_cfs_runtime() loop")
        /*
         * Add to the _head_ of the list, so that an already-started
         * distribute_cfs_runtime will not see us
         */
        list_add_rcu(&cfs_rq->throttled_list, &cfs_b->throttled_cfs_rq);
        // [...]
}
```

即是说，极端情况下，如果每次 distribute_cfs_runtime 都没有足够的配额去 unthrottle 所有 cfs_rq，那么处于 throttled_cfs_rq 链表头部的队列，在获取 CPU 配额并再次耗尽后，会重新进入 throttled_cfs_rq 链表的头部，而链表尾部的 cfs_rq 则会一直处于 throttle 状态，其队列上的进程得不到调度。

此时，distribute_cfs_runtime 分配给每个队列的时间，相等于上一次 `update_curr -> account_cfs_rq_runtime -> __account_cfs_rq_runtime` 中的 delta_exec，即两次 update_curr 之间的时间差：

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
        // delta_exec 为一上次调用 update_curr 到本次调用的时间差
        account_cfs_rq_runtime(cfs_rq, delta_exec);
}  

// kernel/sched/fair.c
static void __account_cfs_rq_runtime(struct cfs_rq *cfs_rq, u64 delta_exec)
{       
        // [...]
        cfs_rq->runtime_remaining -= delta_exec;
        // cfs_rq->runtime_remaining 变为负，且后续无法获得更多配额，就会 throttle
        // 参考 distribute_cfs_runtime 代码，每次 unthrottle 后 runtime_remaining = 1
        // 减去 delta_exec 后变为负值 1-delta_exec，后续无法获得更多配额，触发 throttle
        // distribute_cfs_runtime 下次再分配的配额即 -(1-delta_exec)+1 = delta_exec
        // [...]
}
```

这个 delta_exec 的期望值取决于系统配置的 CFS 参数以及当时队列上的实际负载。一般是两次上下文切换之间的时间差（update_curr 在多个地方被调用到，但最频繁的还是进程切换时调用），通常为毫秒级，我们保守估计为 3ms（考虑到当前队列上的负载并不高，应该安全）。而 runc:[2:INIT] 所在的进程组，CPU 总配额为 40000000ns == 40ms:

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

假如调用 distribute_cfs_runtime 时，每个 cfs_rq 分配 3ms，则 quota 只够分配大约 14 个 cfs_rq，throttled_cfs_rq 链表中第14个之后的 cfs_rq 可能永远处于 throttled 状态。

检查 runc:[2:INIT] 进程所在的 cfs_rq （`0xffff97e02f8b8800`） 在 throttled_cfs_rq 链表中的位置，排在第 21 位：

```
crash> p &((struct task_group*)0xffff97e59a147900)->cfs_bandwidth.throttled_cfs_rq
$1 = (struct list_head *) 0xffff97e59a147b78

crash> list -H 0xffff97e59a147b78 -o cfs_rq.throttled_list | awk '{print NR, $0}' | grep ffff97e02f8b8800
21 ffff97e02f8b8800
```
这就能解释得通为什么这个 cfs_rq 上的进程处于 R 状态超过 2 分钟没有得到调度。

## 根因

 CFS 调度器本身无法很好的保障跨 CPU 的调度公平性，尤其是当进程组的 CPU 资源受限时，当前 v4.x 的内核 CFS 带宽控制有缺陷，管理 throttled cfs_rq 的链表为后进先出（LIFO），可能导致排在链表尾部的队列上的进程一直得不到配额而被饿死。

本次事故中，进程组是某个被限制了 CPU 资源的容器（`pod427b33b5-c993-41f1-b3f7-c2bbebfee969`），其中被饿死的 runc:[2:INIT] 进程持有了一个 rwsem，连锁反应导致其他等锁的进程被一直阻塞在 D 状态，最终由 khungtaskd 触发了系统重启。

# 解决方案<a id="solution"></a>

1. <a id="solution-1"></a>修改 cgoup 参数，等比例放大 cpu.cfs_quota_us 和 cpu.cfs_period_us，使每次刷新配额时，进程组有足够的配额分配给所有 throttled 状态的 cfs_rq。因为 period 也变大了，所以代价是进程的调度延时可能会变高。
2. <a id="solution-2"></a>把进程组绑核在更少的 CPU 上，每次需要 unthrottle 的 CFS 队列会相应减少。
3. <a id="solution-3"></a>升级kernel（即升级 OS），CFS 带宽控制用 LIFO 管理 throttled cfs_rq 导致链表尾部队列饿死的问题，在 v5.8 中完全修复，参考[附录](#appendix-2)中 cgroup 维护者梳理的历史变更。


## 附录：rwsem_waiter 分析<a id="appendix-1"></a>
返回[原文↩︎](#back-rwsem_waiter-analysis)

等 rwsem 的时候，进程会在内核栈中放置一个 rwsem_waiter 结构体，其 task 成员指向当前进程本身。当获得锁的时候，等锁进程的 waiter.task 会被设置为 null，然后被唤醒，检测 waiter.task 为 null 判断获锁成功并退出等待循环：

```c
// kernel/locking/rwsem-xadd.c
// 等待 rwsem 时调用
static inline struct rw_semaphore __sched *
__rwsem_down_read_failed_common(struct rw_semaphore *sem, int state)
{
        // [...]
        struct rwsem_waiter waiter;
        DEFINE_WAKE_Q(wake_q);

		// 在堆栈上建立一个 rwsem_waiter 并加入 rwsem 的等待队列
        waiter.task = current;
        waiter.type = RWSEM_WAITING_FOR_READ;
        // [...]
        list_add_tail(&waiter.list, &sem->wait_list);

        // [...]
        // 循环等锁
        while (true) {
                set_current_state(state);
                // waiter 为 null 即成功获得锁，退出循环
                if (!waiter.task)
                        break;
                // [...]
                schedule();
        }
        // [...]
}

// kernel/locking/rwsem-xadd.c
// rwsem 释放后由释放者调用，重新分配 rwsem 并唤醒相关的等锁进程
static void __rwsem_mark_wake(struct rw_semaphore *sem,
                              enum rwsem_wake_type wake_type,
                              struct wake_q_head *wake_q)
{
		struct rwsem_waiter *waiter, *tmp;
        // [...]
        list_for_each_entry_safe(waiter, tmp, &sem->wait_list, list) {
                struct task_struct *tsk;

                if (waiter->type == RWSEM_WAITING_FOR_WRITE)
                        break;
				// 这行之后 tsk 将成功获取 rwsem 并被唤醒
				// [...]

				// 将 task 移除 rwsem 的等待队列
                get_task_struct(tsk);
                list_del(&waiter->list);

                // [...]
                // waiter.task 被设置为 null
                smp_store_release(&waiter->task, NULL);
                // [...]
        }
        // [...]
}
```

因此，若 rwsem_down_read_failed 堆栈上 rwsem_waiter 里的 tsk 成员为 null，也即意味着进程是否已经获取到 rwsem。通过 bt -F 打印出来的堆栈中，容易找到这个 rwsem_waiter （可以通过 crash 反汇编确认偏移量，不赘述）：

```
crash> foreach bt -F | grep -a20 cgroup_threadgroup_rwsem
[...]
#2 [ffffb198bb80bd20] rwsem_down_read_failed at ffffffffb3754caf  
ffffb198bb80bd28: 0000000000000000 0000000000000001  
ffffb198bb80bd38: ffffb198bb80bd30 ffffb198b95b7cd8  <====== rwsem_waiter 结构体，第一个成员为 list_head
ffffb198bb80bd48: ffffb198b95b7cd8 0000000000000000  <====== task == null
ffffb198bb80bd58: ffff97e400000001 ffffb198bb80bec0  <====== type == 00000001，即 RWSEM_WAITING_FOR_READ
ffffb198bb80bd68: cgroup_threadgroup_rwsem 00000000003d0f00  
ffffb198bb80bd78: 00000000c07db980 ffffb198bb80bec0  
ffffb198bb80bd88: call_rwsem_down_read_failed+20  
[...]
```

其中：
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

## 附录：Maintainer Note on Patch History<a id="appendix-2"></a>
返回[原文↩︎](#solution)

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

## 脚注


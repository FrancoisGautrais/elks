#ifndef LX86_LINUXMT_SCHED_H
#define LX86_LINUXMT_SCHED_H

#define MAX_TASKS 15
#define NGROUPS	13		/* Supplementary groups */
#define NOGROUP 0xFFFF
#define KSTACK_BYTES 1024	/* Size of kernel stacks */

#define   SCHED_OTHER 		0
#define   SCHED_RR 			1
#define   SCHED_FIFO 		2
#define   SCHED_FIFO 		3
#define   SCHED_BATCH 		4

#define MAX_PRIO 8
#define CONFIG_RT


#include <linuxmt/types.h>
#include <linuxmt/fs.h>
#include <linuxmt/time.h>
#include <linuxmt/signal.h>
#include <linuxmt/autoconf.h>
#include <linuxmt/wait.h>
#include <linuxmt/ntty.h>
#include <linuxmt/timex.h>

#ifdef CONFIG_STRACE
#include <linuxmt/strace.h>
#endif

#include <arch/param.h>


struct file_struct {
    fd_mask_t			close_on_exec;
    struct file 		*fd[NR_OPEN];
};

struct fs_struct {
    unsigned short int		umask;
    struct inode		*root;
    struct inode		*pwd;
};



struct mm_struct {
    seg_t			cseg;
    seg_t			dseg;
    char			flags;
#define CS_SWAP		1
#define DS_SWAP		2
};

struct signal_struct {
    struct sigaction		action[NSIG];
};

struct task_struct {


/* Timing */
	
/* Executive stuff */
    __registers 		t_regs;
    __pptr			t_enddata;
    __pptr			t_begstack;
    __pptr			t_endbrk;
    __pptr			t_endseg;

/* Kernel info */
    pid_t			pid;
    pid_t			ppid;
    pid_t			session;
    uid_t			uid;
    uid_t			euid;
    uid_t			suid;
    gid_t			gid;
    gid_t			egid;
    gid_t			sgid;
    
/* Scheduling + status variables */

#ifdef CONFIG_RT
    prio_t 			prio;
    prio_pol_t		policy;
#endif
 
#ifdef CONFIG_CALC_TIME
	jiff_t 			start_time;
	jiff_t 			exec_time;
#endif
	
    __s16			state;
    __u32			timeout;	/* for select() */
    struct wait_queue		*waitpt;	/* Wait pointer */
    __u16			pollhash;
    struct task_struct		*next_run;
    struct task_struct		*prev_run;
    struct file_struct		files;		/* File system structure */
    struct fs_struct		fs;		/* File roots */
    struct mm_struct		mm;		/* Memory blocks */
    pid_t			pgrp;
    struct tty			*tty;
    struct task_struct		*p_parent;
    struct task_struct		*p_prevsib;
    struct task_struct		*p_nextsib;
    struct task_struct		*p_child;	 
    struct wait_queue		child_wait;
    pid_t			child_lastend;
    int 			lastend_status;
    struct inode		* t_inode;
    sigset_t			signal;		/* Signal status */
    struct signal_struct	sig;		/* Signal block */
    int 			dumpable;	/* Can core dump */

#ifdef CONFIG_SWAP
    jiff_t			last_running;
#endif

#ifdef CONFIG_SUPPLEMENTARY_GROUPS
    gid_t			groups[NGROUPS];
#endif

#ifdef CONFIG_STRACE
    struct syscall_params	sc_info;
#endif

    __u16			t_kstackm;	/* To detect stack corruption */
    __u8			t_kstack[KSTACK_BYTES];
};

#define KSTACK_MAGIC 0x5476

#define TASK_RUNNING 		0
#define TASK_INTERRUPTIBLE	1
#define TASK_UNINTERRUPTIBLE 	2
#define TASK_ZOMBIE		3
#define TASK_STOPPED		4
#define TASK_SWAPPING		5
#define TASK_UNUSED		6
#define TASK_WAITING		7
#define TASK_EXITING		8

/*@-namechecks@*/

/* We use typedefs to avoid using struct foobar (*) */
typedef struct task_struct __task, *__ptask;

/*@+namechecks@*/

extern load_regs(__ptask);
extern save_regs(__ptask);


extern jiff_t jiffies;
extern __ptask current;		/* next; */
extern int need_resched;

extern struct timeval xtime;
#define CURRENT_TIME ((xtime.tv_sec) + (jiffies/HZ))

#define for_each_task(p) \
	for (p = &task[0] ; p!=&task[MAX_TASKS]; p++ )



/* Scheduling and sleeping function prototypes */

extern void schedule(void);

extern void wait_set(struct wait_queue *);
extern void wait_clear(struct wait_queue *);
extern void sleep_on(struct wait_queue *);
extern void interruptible_sleep_on(struct wait_queue *);

/*@-namechecks@*/

extern void _wake_up(struct wait_queue *,unsigned short int);

/*@+namechecks@*/

extern void down(short int *);
extern void up(short int *);

extern void wake_up_process(struct task_struct *);

extern int kill_process(pid_t,sig_t,int);

extern void add_to_runqueue(struct task_struct *);

extern struct task_struct *find_empty_process(void);
extern void arch_build_stack(struct task_struct *, char *);
extern unsigned int get_ustack(struct task_struct *,int);
extern void put_ustack(register struct task_struct *,int,int);

extern void tswitch(void);
/* This should be an inline function !!! */
extern void select_wait(struct wait_queue *);





extern __task task[MAX_TASKS];
	
	
/* RT functions */
#ifdef CONFIG_RT
	extern __ptask rt_tasks[MAX_PRIO];
	
	
	extern void print_rt_tasks(char* str);
	extern __ptask find_process_by_pid(pid_t pid);
	 struct sched_param
	 {
		 int sched_priority;
	 };

	extern int sys_sched_setscheduler(pid_t pid, int policy,
							struct sched_param *param);

	extern int sys_sched_getscheduler(pid_t pid);
	extern int sys_sched_setparam(pid_t pid, struct sched_param* param);
	extern int sys_sched_getparam(pid_t pid, struct sched_param* param);
#endif

#endif

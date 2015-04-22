/*
 *  kernel/sched.c
 *  (C) 1995 Chad Page
 *
 *  This is the main scheduler - hopefully simpler than Linux's at present.
 *
 *
 */

/* Commnent in below to use the old scheduler which uses counters */

#include <linuxmt/kernel.h>
#include <linuxmt/sched.h>
#include <linuxmt/init.h>
#include <linuxmt/errno.h>
#include <linuxmt/timer.h>
#include <linuxmt/string.h>
#include <linuxmt/mm.h>

#include <arch/irq.h>

#define init_task task[0]

__ptask rt_tasks[MAX_PRIO];

__task task[MAX_TASKS];
unsigned char nr_running;

__ptask current = task;
__ptask previous;

extern int intr_count;

static void run_timer_list();

void print_rt_tasks(char* str)
{
	int i;
	//return;
	printk("%s: ( ", str);
	for(i=0; i<MAX_PRIO; i++) printk("(%x,%x) ", (!rt_tasks[i])?15:rt_tasks[i]->pid, (!rt_tasks[i] || !rt_tasks[i]->next_run)?15:rt_tasks[i]->next_run->pid);
	printk(")\n");
}

char* get_task_sched_name(int sched)
{
	switch(sched)
	{
		case SCHED_BATCH: return "SCHED_BATCH";
		case SCHED_OTHER: return "SCHED_OTHER";
		case SCHED_RR: return "SCHED_RR";
		case SCHED_FIFO: return "SCHED_FIFO";
		default: return "SCHED_????";
	}
}

char* get_task_state_name(int state)
{
	switch(state)
	{
		case TASK_EXITING: return "TASK_EXITING";
		case TASK_INTERRUPTIBLE: return "TASK_INTERRUPTIBLE";
		case TASK_RUNNING: return "TASK_RUNNING";
		case TASK_STOPPED: return "TASK_STOPPED";
		case TASK_SWAPPING: return "TASK_SWAPPING";
		case TASK_UNINTERRUPTIBLE: return "TASK_UNINTERRUPTIBLE";
		case TASK_UNUSED: return "TASK_UNUSED";
		case TASK_WAITING: return "TASK_WAITING";
		case TASK_ZOMBIE: return "TASK_ZOMBIE";
		default: return "TASK_??????";
	}
}



void add_to_runqueue(register struct task_struct *p)
{
	int i;
    nr_running++;
    if(p->policy == SCHED_RR || p->policy == SCHED_FIFO )
    {
		
		if(p->prio>= MAX_PRIO)
		{
			printk("Error task %d has too high priority\n", p->prio);
			return;
		}
		
		printk("[%d]", p->pid); print_rt_tasks("add: debut :");
		if(!rt_tasks[p->prio])
		{
			rt_tasks[p->prio]=p;
			p->prev_run=p->next_run=p;
		}else
		{
			p->prev_run=rt_tasks[p->prio]->prev_run;
			rt_tasks[p->prio]->prev_run->next_run=p;
			rt_tasks[p->prio]->prev_run=p;
			p->next_run=p;
		}
		
		
		print_rt_tasks("add: fin :");
		return;
	}
    (p->prev_run = init_task.prev_run)->next_run = p;
    p->next_run = &init_task;
    init_task.prev_run = p;
}

void del_from_runqueue(register struct task_struct *p)
{
#if 0       /* sanity tests */
    if (!p->next_run || !p->prev_run) {
    printk("task %d not on run-queue (state=%d)\n", p->pid, p->state);
    return;
    }
#endif

    nr_running--;
	if(p->policy == SCHED_RR || p->policy == SCHED_FIFO)
	{
		/* only one task in rtrq */ 
		
		printk("[%d]", p->pid); print_rt_tasks("del: debut :");
		printk("[%x -> (%x) -> %x]\n", (!p->prev_run)?15:p->prev_run->pid, (!p)?15:p->pid, (!p->next_run)?15:p->next_run->pid);
		if(p==p->prev_run && p==p->next_run)
		{
			rt_tasks[p->prio]=NULL;
		}
		else if(p==p->next_run) //on supprime la fin
		{
			register __ptask pp=p->prev_run;
			p->prev_run=p->prev_run->prev_run;
			pp->next_run=p->prev_run;
		}else
		{
			rt_tasks[p->prio]=p->next_run;
			p->next_run->prev_run=p->prev_run;
		}
		p->next_run = p->prev_run = NULL;
		print_rt_tasks("del: fin2 :");
		return;
	}
	
    if (p == &init_task) {
        printk("idle task may not sleep\n");
        return;
    }
    (p->next_run->prev_run = p->prev_run)->next_run = p->next_run;
    p->next_run = p->prev_run = NULL;
#ifdef CONFIG_SWAP
    p->last_running = jiffies;
#endif

}


static void process_timeout(int __data)
{
    register struct task_struct *p = (struct task_struct *) __data;

#if 0
    printk("process_timeout called!  data=%x, waking task %d\n", __data,
       p->pid);
#endif
    p->timeout = 0UL;
    wake_up_process(p);
}


__ptask find_next_task(__ptask prev)
{
	prio_pol_t rtt;
	for(rtt=0; rtt<MAX_PRIO; rtt++)
		if(rt_tasks[rtt]) 
			return rt_tasks[rtt];
	return prev->next_run;
}


/*
 *  Schedule a task. On entry current is the task, which will
 *  vanish quietly for a while and someone elses thread will return
 *  from here.
 */

void schedule(void)
{
    register __ptask prev;
    register __ptask next;
    jiff_t timeout = 0UL;
    prev = current;
    next =find_next_task(prev);
    
    if (prev->t_kstackm != KSTACK_MAGIC)
        panic("Process %d exceeded kernel stack limit! magic %x\n", 
            prev->pid, prev->t_kstackm);
    /* We have to let a task exit! */
    if (prev->state == TASK_EXITING)
        return;

	
	//printk("%s : %d -> %s\n", get_task_sched_name(prev->policy), prev->pid, get_task_state_name(prev->state));
    clr_irq();
    switch (prev->state) {
		case TASK_INTERRUPTIBLE:
			if (prev->signal /* & ~prev->blocked */ )
				goto makerunnable;

			timeout = prev->timeout;

			if (prev->timeout && (prev->timeout <= jiffies)) {
				prev->timeout = timeout = 0UL;
makerunnable:
				prev->state = TASK_RUNNING;
				break;
			}
			//if(prev->policy==SCHED_RR || prev->policy==SCHED_FIFO) break;
			
		default:
		/**
		 * bug dans la fonction del_runqueu
		 * quand le pere attends le fils
		 * 
		 * */
			 del_from_runqueue(prev);
			 if(next==prev)
			 {
				 next=find_next_task(prev);
				 printk("next=%d==%d\n", next, prev);
				 if(!next || next==prev) next=init_task.next_run;
				 if(next->state == TASK_UNUSED) {printk("Error task unused selected (%d,%d,%d)", next, next->pid, prev); while(1);}
			     //panic("ici (%d, %d)\n", next->pid);
			 }
			/*break; */
		case TASK_RUNNING:
			;
    }
    set_irq();
    
    
    
    if(next == &init_task)
        next = next->next_run;
        
    if (intr_count > 0)
        goto scheduling_in_interrupt;

	//printk("c -> %d, %s\n", next->pid, get_task_state_name(next->state));
	//printk("->%d -> %d %d \n", prev->pid, next->pid, jiffies);
    if (next != prev) {
        struct timer_list timer;

        if ((prev->policy!=SCHED_RR && prev->policy!=SCHED_FIFO) && timeout) {
            init_timer(&timer);
            timer.tl_expires = timeout; 
            timer.tl_data = (int) prev;
            timer.tl_function = process_timeout;
            add_timer(&timer);
        }

#ifdef CONFIG_SWAP
        if(do_swapper_run(next) == -1){
            printk("Can't become runnable %d\n", next->pid);
            panic("");
        }
#endif

        previous = prev;
        current = next;
        tswitch();  /* Won't return for a new task */
        if (timeout) {
            del_timer(&timer);
        }
    }

    return;

scheduling_in_interrupt:

    /* Taking a timer IRQ during another IRQ or while in kernel space is
     * quite legal. We just dont switch then */
/*     if (intr_count > 0) */
        printk("Aiee: scheduling in interrupt %d - %d %d\n",
           intr_count, next->pid, prev->pid);
}

struct timer_list tl_list = { NULL, NULL, 0L, 0, NULL };

static int detach_timer(struct timer_list *timer)
{
    register struct timer_list *next;
    register struct timer_list *prev;
    next = timer->tl_next;
    prev = timer->tl_prev;
    if (next) {
        next->tl_prev = prev;
    }
    if (prev) {
        prev->tl_next = next;
		return 1;
    }
    return 0;
}

int del_timer(register struct timer_list *timer)
{
    int ret;
    flag_t flags;
    save_flags(flags);
    clr_irq();
    ret = detach_timer(timer);
    timer->tl_next = timer->tl_prev = 0;
    restore_flags(flags);
    return ret;
}

void init_timer(register struct timer_list *timer)
{
    timer->tl_next = timer->tl_prev = NULL;
}

void add_timer(register struct timer_list *timer)
{
    flag_t flags;
    register struct timer_list *next = &tl_list;
    struct timer_list *prev;

    save_flags(flags);
    clr_irq();

    do {
        prev = next;
    } while((next = next->tl_next) && (next->tl_expires < timer->tl_expires));

    (timer->tl_prev = prev)->tl_next = timer;
    if((timer->tl_next = next))
        next->tl_prev = timer;

    restore_flags(flags);
}

static void run_timer_list(void)
{
    register struct timer_list *timer;

    clr_irq();
    while ((timer = tl_list.tl_next) && timer->tl_expires <= jiffies) {
        detach_timer(timer);
        timer->tl_next = timer->tl_prev = NULL;
        set_irq();
        timer->tl_function(timer->tl_data);
        clr_irq();
    }
    set_irq();
}

/* maybe someday I'll implement these profiling things -PL */

#if 0

static void do_it_prof(struct task_struct *p, jiff_t ticks)
{
    jiff_t it_prof = p->it_prof_value;

    if (it_prof) {
    if (it_prof <= ticks) {
        it_prof = ticks + p->it_prof_incr;
        send_sig(SIGPROF, p, 1);
    }
    p->it_prof_value = it_prof - ticks;
    }
}

static void update_one_process(struct taks_struct *p,
                   jiff_t ticks, jiff_t user, jiff_t system)
{
    do_process_times(p, user, system);
    do_it_virt(p, user);
    do_it_prof(p, ticks);
}

#endif

void do_timer(struct pt_regs *regs)
{
    jiffies++;
	
#ifdef NEED_RESCHED		/* need_resched is not checked anywhere */
    if (!((int) jiffies & 7))
	need_resched = 1;	/* how primitive can you get? */
#endif

    run_timer_list();

}

__ptask find_process_by_pid(pid_t pid)
{
	register __ptask p;
	for_each_task(p)
		if(p->pid==pid && p->state!=TASK_UNUSED)
			return p;
	return NULL;
}


void sched_init(void)
{
    register struct task_struct *t = task;
	register prio_t rtt = 0;
/*
 *	Mark tasks 0-(MAX_TASKS-1) as not in use.
 */
 
 
    do {
		t->state = TASK_UNUSED;
    } while(++t < &task[MAX_TASKS]);
	
	for(; rtt < MAX_PRIO; rtt++)
		rt_tasks[rtt]=NULL;
	
	
/*
 *	Now create task 0 to be ourself.
 */
    kfork_proc(NULL);

    t = task;
    t->state = TASK_RUNNING;
    t->next_run = t->prev_run = t;
}

int sys_sched_setscheduler(pid_t pid, int policy,   
										struct sched_param  *param){
	__ptask t=find_process_by_pid(pid);
	struct sched_param p;
	memcpy_fromfs(&p, param, sizeof(struct sched_param));
	//printk("sys_sched_setscheduler( %d, %d, %d (%d))\n",pid, policy, &p, p.sched_priority);
	
	if(!t) return  -ESRCH;
	print_rt_tasks("setschedule: debut :");
	del_from_runqueue(t);
	
	t->policy=policy;
	t->prio=(prio_t)p.sched_priority;
	add_to_runqueue(t);
	print_rt_tasks("setschedule: fin :");
	
	schedule();
	
	
	return 0;
}

int sys_sched_getscheduler(pid_t pid)
{
	__ptask t=find_process_by_pid(pid);
	//printk("sys_sched_getscheduler(%d) = %d\n",pid,  t->policy);
	
	if(!t) return  -ESRCH;
	
	return t->policy;
}

int sys_sched_setparam(pid_t pid, struct sched_param* param)
{
	__ptask t=find_process_by_pid(pid);
	struct sched_param p;
	memcpy_fromfs(&p, param, sizeof(struct sched_param));
	//printk("sys_sched_setparam(%d, %d)\n",pid,  p.sched_priority);
	
	if(!t) return  -ESRCH;
	
	print_rt_tasks("setparam: debut :");
	del_from_runqueue(t);
	t->prio=p.sched_priority;
	add_to_runqueue(t);
	print_rt_tasks("setparam: fin :");
	
	schedule();
	return 0;
}

int sys_sched_getparam(pid_t pid, struct sched_param* param)
{
	__ptask t=find_process_by_pid(pid);
	struct sched_param p;
	//printk("sys_sched_getparam(%d) = %d\n",pid,  t->prio);
	
	if(!t) return  -ESRCH;
	p.sched_priority=t->prio;
	memcpy_tofs(param, &p, sizeof(struct sched_param) );
	
	return 0;
}

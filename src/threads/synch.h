#ifndef THREADS_SYNCH_H
#define THREADS_SYNCH_H

#include <list.h>
#include <stdbool.h>


/* A counting semaphore. */
struct semaphore 
{
    unsigned value;             /* Current value. */
    struct list waiters;       /* List of waiting threads. */
};

/* Lock. */
struct lock 
  {
    struct thread *holder;      /* Thread holding lock (for debugging). */
    struct semaphore semaphore; /* Binary semaphore controlling access. */
    struct list_elem lock_elem;
    struct list_elem lock_elem2;
    int holder_prev_priority;  // holder's primitive priority value
    int donated_priority;
  };


#ifdef USERPROG
#endif

void sema_init (struct semaphore *, unsigned value);
void sema_down (struct semaphore *);
bool sema_try_down (struct semaphore *);
void sema_up (struct semaphore *);
void sema_self_test (void);


void check_donate_cond(struct lock *);
void restore_prev_priority(struct lock *); 
bool lock_compare_priority(struct list_elem* , struct list_elem* , void* UNUSED); 
void lock_insert_holdinglocks(struct lock*); 
unsigned testandset(unsigned * , unsigned );


void lock_init (struct lock *);
void lock_acquire (struct lock *);
bool lock_try_acquire (struct lock *);
void lock_release (struct lock *);
bool lock_held_by_current_thread (const struct lock *);

/* Condition variable. */
struct condition 
  {
    struct list waiters;        /* List of waiting threads. */
  };


void cond_init (struct condition *);
void cond_wait (struct condition *, struct lock *);
void cond_signal (struct condition *, struct lock *);
void cond_broadcast (struct condition *, struct lock *);
bool cond_compare_priority(struct list_elem * , struct list_elem * , void * UNUSED);


struct thread *get_max_priority_thread(struct list *);
bool is_contain(struct list *, struct list_elem *);

/* Optimization barrier.

   The compiler will not reorder operations across an
   optimization barrier.  See "Optimization Barriers" in the
   reference guide for more information.*/
#define barrier() asm volatile ("" : : : "memory")

#endif /* threads/synch.h */

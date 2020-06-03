#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "userprog/gdt.h"
#include "userprog/pagedir.h"
#include "userprog/tss.h"
#include "userprog/syscall.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"

#include "threads/malloc.h"
#include "threads/synch.h"

#ifdef VM
#include "vm/page.h"
#endif


static thread_func start_process NO_RETURN;
static bool load (const char *cmdline, void (**eip) (void), void **esp);
static bool setup_args(void **esp , char *file_name);
static int parse_command(char *input , char **output);

/* Starts a new thread running a user program loaded from
   FILENAME.  The new thread may be scheduled (and may even exit)
   before process_execute() returns.  Returns the new process's
   thread id, or TID_ERROR if the thread cannot be created. */
tid_t
process_execute (const char *file_name)
{
  char *fn_copy;
  tid_t tid;

  /* Make a copy of FILE_NAME.
     Otherwise there's a race between the caller and load(). */
  fn_copy = palloc_get_page (0);
  if (fn_copy == NULL)
    return TID_ERROR;
  strlcpy (fn_copy, file_name, PGSIZE);

  /* Create a new thread to execute FILE_NAME. */
  tid = thread_create (file_name, PRI_DEFAULT, start_process, fn_copy);

  if(tid == TID_ERROR){
     palloc_free_page(fn_copy);
     return tid;
  }

  // find child thread using tid from parent's child list
  struct thread *new_child = find_thread_by_tid(tid, &thread_current()->child_list);
  ASSERT(new_child != NULL);
 
 lock_acquire(&new_child->Lock);

  while(new_child->load_done == 0){  //check if child load is done.
        cond_wait(&new_child->Cond, &new_child->Lock);  // child didn't finished the load so wait
  }

  lock_release(&new_child->Lock);

  if(!new_child->load_status){
        tid=-1;  // child failed load by some reason so return -1
        list_remove(&new_child->child_elem);
  }

  return tid;
}


/* A thread function that loads a user process and starts it
   running. */
static void
start_process (void *file_name_)
{
  char *file_name=file_name_;
  char *save_ptr;
  struct intr_frame if_;
  bool success;

  struct thread *cur = thread_current();  // get current thread
 
  list_init(&cur->vm); //initialize the vm list

  
  char copy_file_name[strlen(file_name) + 1];

  strlcpy(copy_file_name, file_name, strlen(file_name) + 1);

  // get process name using strtok func
  char *process_name = strtok_r(copy_file_name, " ", &save_ptr);

  /* Initialize interrupt frame and load executable. */
  memset (&if_, 0, sizeof if_);
  if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
  if_.cs = SEL_UCSEG;
  if_.eflags = FLAG_IF | FLAG_MBS;

  success = load (process_name, &if_.eip, &if_.esp); // load process

  strlcpy(copy_file_name, file_name, strlen(file_name) + 1);

  if(success){  // setup arguments & check stack page overflow
      success = setup_args(&if_.esp, copy_file_name);
  }

/*
 This block is finding the corresponding cond_wait structure and release lock
*/

  cur->fd = (struct file **) malloc(128*sizeof(struct file*));
  memset(cur->fd,0,128*sizeof(struct file*)); // initial max file descriptor size is 128

  lock_acquire(&cur->Lock);
    cur->load_status = success;             // set load_status
    cond_signal(&cur->Cond, &cur->Lock);
  lock_release(&cur->Lock);

  /* If load failed, quit. */
  palloc_free_page (file_name);
  if (!success){
     thread_exit ();
  }

  /* Start the user process by simulating a return from an
     interrupt, implemented by intr_exit (in
     threads/intr-stubs.S).  Because intr_exit takes all of its
     arguments on the stack in the form of a `struct intr_frame',
     we just point the stack pointer (%esp) to our stack frame
     and jump to it. */
  asm volatile ("movl %0, %%esp; jmp intr_exit" : : "g" (&if_) : "memory");
  NOT_REACHED ();
}

/*
This function setup argments
*/
static
bool setup_args(void **esp , char *command){
   char *result[40];
   int argc = parse_command(command,result);
   char *argv[argc];
   uint8_t word_align_num;
   int i,len,total_len = 0;

   for(i = argc-1 ; i >= 0 ; i--){
     len = strlen(result[i])+1;
     *esp -= len;
     strlcpy(*esp,result[i],len);
     argv[i] = *esp;   // save the pointer for later save.
     total_len += len;
   }

  word_align_num = total_len %4 == 0? 0 : 4 - (total_len % 4); // if word_aligned ? then subtract 0 : if not word alinged
  *esp -= word_align_num;

  if ((total_len + word_align_num*sizeof(uint8_t) + (argc+1)*sizeof(char *) + sizeof(char **) 
       + sizeof(int) + sizeof(void *)) > PGSIZE){
     return false;
  }

  *esp -= 4;
  **(uint32_t **) esp = (uint32_t) 0;   // save the null 

  for(i = argc-1 ; i >= 0 ; i--){
    *esp -= 4;
    **(uint32_t **)esp = (uint32_t) argv[i];  // save argv[0] argv[1]...
  }

 *esp -= 4;
 **(uint32_t **)esp = (uint32_t) *esp+4; // argv

 *esp -= 4;
 **(uint32_t **)esp = (uint32_t) argc; // argc

 *esp -= 4;
 **(uint32_t **)esp = (uint32_t) 0; // fake address;

  return true;
}


/*
This function extract argc and argv from input argment
*/
static
int parse_command(char* input, char **argv){
  int argc = 1;
  char *save_ptr;
  argv[argc-1] = strtok_r(input," ",&save_ptr); // split based on space
  while(true){
	argv[argc] = strtok_r(NULL," ",&save_ptr);
	if(argv[argc] == NULL ) break;
	argc++;
  }
  return argc;
}


/* Waits for thread TID to die and returns its exit status.  If
   it was terminated by the kernel (i.e. killed due to an
   exception), returns -1.  If TID is invalid or if it was not a
   child of the calling process, or if process_wait() has already
   been successfully called for the given TID, returns -1
   immediately, without waiting.

   This function will be implemented in problem 2-2.  For now, it
   does nothing. */
int
process_wait (tid_t child_tid ) 
{

  // find child from parent's child list
  struct thread *t_child = find_thread_by_tid(child_tid, &thread_current()->child_list);

  if(t_child == NULL) return -1; // if cond_lock is not found, thend return -1

  lock_acquire(&t_child->Lock);                 // acquire lock
  while(t_child->child_done == 0){              // check already done
    cond_wait(&t_child->Cond, &t_child->Lock);  // it is not done so wait until child done
  }
  lock_release(&t_child->Lock);                 // release lock

  int exit_status = t_child->exit_status;

  sema_up(&t_child->parent_wait);

  list_remove(&t_child->child_elem);  // remove child from parent's child_list

  return exit_status;
}

/* Free the current process's resources. */
void
process_exit (void)
{
  struct thread *cur = thread_current ();
  uint32_t *pd;


 /* Close all the file that opened */
  int i;
  for(i = 2 ; i < cur->cur_fd; i ++){
	if(thread_current()->fd[i] != NULL){
	  struct file *f = thread_current()->fd[i];
	  file_close(f);
	}
  }
  free(cur->fd);  /* free the file descriptor array */

  /*If there is lock that acquired then release it.*/
  while(!list_empty(&cur->my_locks)){
	struct list_elem *e = list_pop_front(&cur->my_locks);
	struct lock *l = list_entry(e,struct lock,lock_elem2);
	lock_release(l);
  }


/* remove all entry in child_list */
  while(!list_empty(&cur->child_list)){
        struct list_elem *e =list_pop_front(&cur->child_list);
        struct thread *t_child  = list_entry(e, struct thread, child_elem);
	t_child->parent = NULL;
  }
  //added in lab3 
  vm_destroy(cur); //delete vm_entry function

  file_close(cur->cur_execute); // close own executable file

  if(cur->parent != NULL){     // if parent exist
    lock_acquire(&cur->Lock);  // lock acquire
      cur->child_done = 1;       // indicate child finished the execution
      cond_signal(&cur->Cond, &cur->Lock);  //  wake up parent
    lock_release(&cur->Lock);  // release lock
  }

  if(cur->parent != NULL){
    sema_down(&cur->parent_wait); // wait parent permission
  }

  /* Destroy the current process's page directory and switch back
     to the kernel-only page directory. */
  pd = cur->pagedir;
  if (pd != NULL) 
    {
      /* Correct ordering here is crucial.  We must set
         cur->pagedir to NULL before switching page directories,
         so that a timer interrupt can't switch back to the
         process page directory.  We must activate the base page
         directory before destroying the process's page
         directory, or our active page directory will be one
         that's been freed (and cleared). */
      cur->pagedir = NULL;
      pagedir_activate (NULL);
      pagedir_destroy (pd);
    }
}





/* Sets up the CPU for running user code in the current
   thread.
   This function is called on every context switch. */
void
process_activate (void)
{
  struct thread *t = thread_current ();

  /* Activate thread's page tables. */
  pagedir_activate (t->pagedir);

  /* Set thread's kernel stack for use in processing
     interrupts. */
  tss_update ();
}

/* We load ELF binaries.  The following definitions are taken
   from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
typedef uint32_t Elf32_Word, Elf32_Addr, Elf32_Off;
typedef uint16_t Elf32_Half;

/* For use with ELF types in printf(). */
#define PE32Wx PRIx32   /* Print Elf32_Word in hexadecimal. */
#define PE32Ax PRIx32   /* Print Elf32_Addr in hexadecimal. */
#define PE32Ox PRIx32   /* Print Elf32_Off in hexadecimal. */
#define PE32Hx PRIx16   /* Print Elf32_Half in hexadecimal. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
   This appears at the very beginning of an ELF binary. */
struct Elf32_Ehdr
  {
    unsigned char e_ident[16];
    Elf32_Half    e_type;
    Elf32_Half    e_machine;
    Elf32_Word    e_version;
    Elf32_Addr    e_entry;
    Elf32_Off     e_phoff;
    Elf32_Off     e_shoff;
    Elf32_Word    e_flags;
    Elf32_Half    e_ehsize;
    Elf32_Half    e_phentsize;
    Elf32_Half    e_phnum;
    Elf32_Half    e_shentsize;
    Elf32_Half    e_shnum;
    Elf32_Half    e_shstrndx;
  };

/* Program header.  See [ELF1] 2-2 to 2-4.
   There are e_phnum of these, starting at file offset e_phoff
   (see [ELF1] 1-6). */
struct Elf32_Phdr
  {
    Elf32_Word p_type;
    Elf32_Off  p_offset;
    Elf32_Addr p_vaddr;
    Elf32_Addr p_paddr;
    Elf32_Word p_filesz;
    Elf32_Word p_memsz;
    Elf32_Word p_flags;
    Elf32_Word p_align;
  };

/* Values for p_type.  See [ELF1] 2-3. */
#define PT_NULL    0            /* Ignore. */
#define PT_LOAD    1            /* Loadable segment. */
#define PT_DYNAMIC 2            /* Dynamic linking info. */
#define PT_INTERP  3            /* Name of dynamic loader. */
#define PT_NOTE    4            /* Auxiliary info. */
#define PT_SHLIB   5            /* Reserved. */
#define PT_PHDR    6            /* Program header table. */
#define PT_STACK   0x6474e551   /* Stack segment. */

/* Flags for p_flags.  See [ELF3] 2-3 and 2-4. */
#define PF_X 1          /* Executable. */
#define PF_W 2          /* Writable. */
#define PF_R 4          /* Readable. */

static bool setup_stack (void **esp);
static bool validate_segment (const struct Elf32_Phdr *, struct file *);
static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
                          uint32_t read_bytes, uint32_t zero_bytes,
                          bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
   Stores the executable's entry point into *EIP
   and its initial stack pointer into *ESP.
   Returns true if successful, false otherwise. */
bool
load (const char *file_name, void (**eip) (void), void **esp) 
{
  struct thread *t = thread_current ();
  struct Elf32_Ehdr ehdr;
  struct file *file = NULL;
  off_t file_ofs;
  bool success = false;
  int i;

  /* Allocate and activate page directory. */
  t->pagedir = pagedir_create ();
  if (t->pagedir == NULL) 
    goto done;
  process_activate ();

  t->load_done = -3;

  /* Open executable file. */
  lock_acquire(&filesys_lock);
  file = filesys_open (file_name);

  if (file == NULL) 
    {
      t->load_done = -1; // negative value -> fail
      printf ("load: %s: open failed\n", file_name);
      goto done; 
    }

  t->cur_execute = file;  // make this process to point this executable file. - 
  
  file_deny_write(file);  // prevent from modified by other. - 


  /* Read and verify executable header. */
  if (file_read (file, &ehdr, sizeof ehdr) != sizeof ehdr
      || memcmp (ehdr.e_ident, "\177ELF\1\1\1", 7)
      || ehdr.e_type != 2
      || ehdr.e_machine != 3
      || ehdr.e_version != 1
      || ehdr.e_phentsize != sizeof (struct Elf32_Phdr)
      || ehdr.e_phnum > 1024) 
    {
      lock_release(&filesys_lock);
      t->load_done = -2;
      printf ("load: %s: error loading executable\n", file_name);
      goto done; 
    }

  /* Read program headers. */
  file_ofs = ehdr.e_phoff;
  for (i = 0; i < ehdr.e_phnum; i++) 
    {
      struct Elf32_Phdr phdr;

      if (file_ofs < 0 || file_ofs > file_length (file))
        goto done;
      file_seek (file, file_ofs);

      if (file_read (file, &phdr, sizeof phdr) != sizeof phdr)
        goto done;
      file_ofs += sizeof phdr;
      switch (phdr.p_type) 
        {
        case PT_NULL:
        case PT_NOTE:
        case PT_PHDR:
        case PT_STACK:
        default:
          /* Ignore this segment. */
          break;
        case PT_DYNAMIC:
        case PT_INTERP:
        case PT_SHLIB:
          goto done;
        case PT_LOAD:
          if (validate_segment (&phdr, file)) 
            {
              bool writable = (phdr.p_flags & PF_W) != 0;
              uint32_t file_page = phdr.p_offset & ~PGMASK;
              uint32_t mem_page = phdr.p_vaddr & ~PGMASK;
              uint32_t page_offset = phdr.p_vaddr & PGMASK;
              uint32_t read_bytes, zero_bytes;
              if (phdr.p_filesz > 0)
                {
                  /* Normal segment.
                     Read initial part from disk and zero the rest. */
                  read_bytes = page_offset + phdr.p_filesz;
                  zero_bytes = (ROUND_UP (page_offset + phdr.p_memsz, PGSIZE)
                                - read_bytes);
                }
              else 
                {
                  /* Entirely zero.
                     Don't read anything from disk. */
                  read_bytes = 0;
                  zero_bytes = ROUND_UP (page_offset + phdr.p_memsz, PGSIZE);
                }
              if (!load_segment (file, file_page, (void *) mem_page,
                                 read_bytes, zero_bytes, writable))
                goto done;
            }
          else
            goto done;
          break;
        }
    }

  /* Set up stack. */
  if (!setup_stack (esp))
    goto done;

  /* Start address. */
  *eip = (void (*) (void)) ehdr.e_entry;

  success = true;
  if(success){
        t->load_done = 1; // positive value -> success
  }

 done:
 lock_release(&filesys_lock);
  /* We arrive here whether the load is successful or not. */
  //file_close (file);   // I don't want to close file until process exit.  -
  // this file will closed at process_exit -
  return success;
}

/* load() helpers. */

static bool install_page (void *upage, void *kpage, bool writable);

/* Checks whether PHDR describes a valid, loadable segment in
   FILE and returns true if so, false otherwise. */
static bool
validate_segment (const struct Elf32_Phdr *phdr, struct file *file) 
{
  /* p_offset and p_vaddr must have the same page offset. */
  if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK)) 
    return false; 

  /* p_offset must point within FILE. */
  if (phdr->p_offset > (Elf32_Off) file_length (file)) 
    return false;

  /* p_memsz must be at least as big as p_filesz. */
  if (phdr->p_memsz < phdr->p_filesz) 
    return false; 

  /* The segment must not be empty. */
  if (phdr->p_memsz == 0)
    return false;
  
  /* The virtual memory region must both start and end within the
     user address space range. */
  if (!is_user_vaddr ((void *) phdr->p_vaddr))
    return false;
  if (!is_user_vaddr ((void *) (phdr->p_vaddr + phdr->p_memsz)))
    return false;

  /* The region cannot "wrap around" across the kernel virtual
     address space. */
  if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
    return false;

  /* Disallow mapping page 0.
     Not only is it a bad idea to map page 0, but if we allowed
     it then user code that passed a null pointer to system calls
     could quite likely panic the kernel by way of null pointer
     assertions in memcpy(), etc. */
  if (phdr->p_vaddr < PGSIZE)
    return false;

  /* It's okay. */
  return true;
}

/* Loads a segment starting at offset OFS in FILE at address
   UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
   memory are initialized, as follows:

        - READ_BYTES bytes at UPAGE must be read from FILE
          starting at offset OFS.

        - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.

   The pages initialized by this function must be writable by the
   user process if WRITABLE is true, read-only otherwise.

   Return true if successful, false if a memory allocation error
   or disk read error occurs. */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
              uint32_t read_bytes, uint32_t zero_bytes, bool writable) 
{
  ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
  ASSERT (pg_ofs (upage) == 0);
  ASSERT (ofs % PGSIZE == 0);

  file_seek (file, ofs);
  while (read_bytes > 0 || zero_bytes > 0) 
    {
      /* Calculate how to fill this page.
         We will read PAGE_READ_BYTES bytes from FILE
         and zero the final PAGE_ZERO_BYTES bytes. */
     size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
     size_t page_zero_bytes = PGSIZE - page_read_bytes;

	 //added in lab 3
	 struct vm_entry *vment = (struct vm_entry *)malloc(sizeof(struct vm_entry));
		 //if not allocated(maybe insufficient memory. etc)
		 if (vment == NULL)
			 return false;
	 vment->file = file;
	 vment->ofs = ofs;
	 vment->upage = upage;
	 vment->read_bytes = page_read_bytes;
	 vment->zero_bytes = page_zero_bytes;
	 vment->writable = writable;
	 vment->is_in_memory = false;
	 vment->owner = thread_current();
	 vment->type = 0;  //VM_BIN
	 list_push_back(&thread_current()->vm, &vment->elem);

	 
      read_bytes -= page_read_bytes;
      zero_bytes -= page_zero_bytes;
      upage += PGSIZE;

	  ofs += page_read_bytes;
    }
  return true;
}

/* Create a minimal stack by mapping a zeroed page at the top of
   user virtual memory. */
static bool
setup_stack (void **esp) 
{
  uint8_t *kpage;
  bool success = false;
  
  
  kpage = palloc_get_page (PAL_USER | PAL_ZERO);
  

  if (kpage != NULL) 
    {
      success = install_page (((uint8_t *) PHYS_BASE) - PGSIZE, kpage, true);
      *esp = PHYS_BASE;
    } 
  else
    {
      palloc_free_page (kpage);
      return false;
    }
   //added in lab3
   void *upage = ((uint8_t *) PHYS_BASE) - PGSIZE; //top of the stack 
   //create vm entry, initialize and insert to vm list
   struct vm_entry *vme = (struct vm_entry *)malloc(sizeof(struct vm_entry));
   if(vme == NULL)
     return false;
  
   //initialize the vm entry
   vme->upage = pg_round_down(upage);
   vme->is_in_memory= true;
   vme-> writable = true;
   vme-> owner = thread_current();
   vme-> type = 0; //VM_BIN
   //insert into list
   list_push_back(&thread_current()->vm, &vme->elem);  

   return success;
}

/* Adds a mapping from user virtual address UPAGE to kernel
   virtual address KPAGE to the page table.
   If WRITABLE is true, the user process may modify the page;
   otherwise, it is read-only.
   UPAGE must not already be mapped.
   KPAGE should probably be a page obtained from the user pool
   with palloc_get_page().
   Returns true on success, false if UPAGE is already mapped or
   if memory allocation fails. */
static bool
install_page (void *upage, void *kpage, bool writable)
{
  struct thread *t = thread_current ();

  /* Verify that there's not already a page at that virtual
     address, then map our page there. */
  return (pagedir_get_page (t->pagedir, upage) == NULL
          && pagedir_set_page (t->pagedir, upage, kpage, writable));
}
//added in lab3(used in page_fault to handle page fault)
bool handle_mm_fault(struct vm_entry *vme) {

	bool success = false;
	
	enum palloc_flags flag = PAL_USER;
	if (vme->read_bytes == 0)
		flag |= PAL_ZERO;
	//get a page and save the pointer to that page
	uint8_t *page_pointer = palloc_get_page(flag);
	//if failed to allocate, return false
	if (page_pointer == NULL)
		return false;
	//check the type of vme
	if (vme->type != 0)
		return false;
	//load the file to that memory page
	success = load_file(page_pointer, vme);
	//if not successfully loaded, return false
	if (!success)
		return false;
	if (!install_page(vme->upage, page_pointer, vme->writable)) {
		palloc_free_page(page_pointer);
		return false;
	}
	vme->is_in_memory = true;

	return true;
}

#include "userprog/syscall.h"
#include "userprog/process.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/synch.h"
#include "devices/input.h"
#include <string.h>

#include "filesys/filesys.h"
#include "filesys/file.h"
#include "filesys/inode.h"
#include "threads/malloc.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"

#ifdef VM
#include "vm/page.h"
#endif


//static struct lock filesys_lock;
static void syscall_handler (struct intr_frame *);
static int find_fd(struct thread *t);
static bool extend_fd(struct thread *t);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init(&filesys_lock);
  lock_init(&load_lock);
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{

  void *stack_pointer = f->esp;

  switch(*(uint32_t *)f->esp){

/*Project 2 and later*/
/*0*/   case SYS_HALT :
		if(!is_user_vaddr(stack_pointer)) exit(-1);
		halt();
	break;
/*1*/   case SYS_EXIT :
		if(!is_user_vaddr(stack_pointer+4)) exit(-1);
		exit((int)*(uint32_t*)(stack_pointer+4));
	break;
/*2*/   case SYS_EXEC : // stack_pointer + 4 = program name
		if(!is_user_vaddr(stack_pointer+4)) exit(-1);
		f->eax = exec((char*)*(uint32_t*)(stack_pointer+4));
	break;
/*3*/   case SYS_WAIT :   // stack_pointer +4 = child_id
		if(!is_user_vaddr(stack_pointer+4)) exit(-1);
		f->eax = wait((pid_t)*(uint32_t*)(stack_pointer+4));
	break;
/*4*/   case SYS_CREATE :
		if(!is_user_vaddr(stack_pointer+8)) exit(-1);
		f->eax = create((char *)*(uint32_t *)(stack_pointer+4),(unsigned)*(uint32_t *)(stack_pointer+8));
	break;
/*5*/   case SYS_REMOVE :
		if(!is_user_vaddr(stack_pointer+4)) exit(-1);
		f->eax = remove((char*)*(uint32_t *)(stack_pointer+4));
	break;
/*6*/   case SYS_OPEN :
		if(!is_user_vaddr(stack_pointer+4)) exit(-1);
		f->eax = open((char*)*(uint32_t*)(stack_pointer+4));
	break;
/*7*/   case SYS_FILESIZE :
		if(!is_user_vaddr(stack_pointer+4)) exit(-1);
		f->eax = filesize((int )*(uint32_t*)(stack_pointer+4));
	break;
/*8*/   case SYS_READ :
		if(!is_user_vaddr(stack_pointer+12)) exit(-1);
		f->eax = read((int)*(uint32_t * )(stack_pointer+4),(void *)*(uint32_t *)(stack_pointer+8), (int)*(uint32_t *)(stack_pointer+12));
	break;
/*9*/   case SYS_WRITE :
		if(!is_user_vaddr(stack_pointer+12)) exit(-1);
		f->eax = write((int)*(uint32_t * )(stack_pointer+4),(void *)*(uint32_t *)(stack_pointer+8), (int)*(uint32_t *)(stack_pointer+12));
		// 1 : file descriptor  2 : buffer adderess 3 : size of write
	break;
/*10*/  case SYS_SEEK :
		if(!is_user_vaddr(stack_pointer+8)) exit(-1);
		seek((int)*(uint32_t *)(stack_pointer+4),(unsigned)*(uint32_t *)(stack_pointer+8));
	break;
/*11*/  case SYS_TELL :
		if(!is_user_vaddr(stack_pointer+4)) exit(-1);
		f->eax = tell((int)*(uint32_t *)(stack_pointer+4));
	break;
/*12*/  case SYS_CLOSE :
		if(!is_user_vaddr(stack_pointer+4)) exit(-1);
		close((int)*(uint32_t *)(stack_pointer+4));
	break;
/*de*/  default:
        break;

  }
}


/* Shutdown power off by calling shudown_power_off() function */
void halt (void){
	shutdown_power_off();
}


/* Terminate the current process */
void exit(int status){
  thread_current()->exit_status = status;  // save exit status
  printf("%s: exit(%d)\n",thread_current()->name,status);
  thread_exit(); //process_exit is at the thread_exit()
}


/* Execute process by command line.
   return the new process's pid */
pid_t exec(const char *cmd_line){
 return process_execute(cmd_line);
}


/* Create new file.
   return if sucess true, or false. */
bool create(const char *file_name , unsigned initial_size){

  if(file_name == NULL || strlen(file_name)==0 ) exit(-1);
  if(strlen(file_name)>100) return false;

  lock_acquire(&filesys_lock);
  bool result = filesys_create(file_name,initial_size);
  lock_release(&filesys_lock);

  return result;
}


/* Parent process waits for a child process.
   return the child's exit_status.
*/
int wait(pid_t pid){
 return process_wait(pid);
}


/* Remove the file.
   return if sucess true, or false. */
bool remove(const char *file){
  lock_acquire(&filesys_lock);
    bool result = filesys_remove(file);
  lock_release(&filesys_lock);

  return result;
}


/* Open the file by using filesys_open if open is success
   then malloc the file_fd and assing current thread's file descriptor pointer.
   return the current file discripter. */
int open(const char *file_name){
//  printf("open %d\n",thread_current()->tid);
  if(file_name == NULL || strlen(file_name) ==0  ) return -1;  // if file_name is null , return -1 error checking is programmer's role.

  lock_acquire(&filesys_lock);
    struct file *f = filesys_open(file_name); // use filesys_open and get file.
  lock_release(&filesys_lock);

  if(f == NULL ){
	 return -1;  // if filesys_open fails then return -1
  }
  int i = find_fd(thread_current());
  if( i == -1 ){
	 if(!extend_fd(thread_current())) return -1;
	 i = find_fd(thread_current());
	 ASSERT(i != -1);
  }


  thread_current()->fd[i] = f; // assign process's file descripotr array 0,1,2 is assinged for std buffer so subtract it. -maybe implementing with hash is more fancy.
  if(thread_current()->cur_fd < i){
    thread_current()->cur_fd = i+1;
  }

  return i;
}


/* Expand the array size */
static bool
extend_fd(struct thread *t){
  struct file ** current =  t->fd;
  int new_size = sizeof(struct file *)*t->max_fd*2;
  struct file ** new =  malloc(new_size); // make new file descriptor array, twice bigger
  if(new == NULL ) return false;
  memset(new,0,new_size);
  memcpy(new,current,new_size/2);
  t->fd = new;
  t->max_fd = t->max_fd*2;
  free(current);
  return true;
}


/* Find the empty index on file_descriptor array*/
static int
find_fd(struct thread *t){
  int i;
  for(i = 2 ;  i < t->max_fd ; i++){
 	if(t->fd[i] == NULL)	return i;  // empty space found
  }
  return -1;  // if not found NULL, file_descriptor is full
}


/* Return the size of file if the file is valid, else -1. */
int filesize(int fd){
  lock_acquire(&filesys_lock);
    struct file *f = thread_current()->fd[fd];
    int length = (f != NULL) ? file_length(f) : -1;
  lock_release(&filesys_lock);

  return length;
}


/* Read bytes from the file or keyboard.
   return the number of read bytes. */
int read(int fd, void *buf, unsigned size){
  unsigned i;
  if(!is_user_vaddr(buf) || buf == NULL)
  {
	 exit(-1);
  }

  if(fd == 0){  // read from keyboard
    for(i = 0 ; i < size ; i++){
        (((char *) buf))[i] = input_getc();
	if(((char *)buf)[i] == '\0') break;
    }
   return i;
  }
  else if(fd == 1 ||fd > thread_current()->max_fd|| fd < 0 ){ // stdout
	return -1;
  }

  else{
     lock_acquire(&filesys_lock);
       struct file *f = thread_current()->fd[fd];
       int read_len = (f != NULL) ? file_read(f,buf,size) : -1;
     lock_release(&filesys_lock);

     return read_len;
  }
}


/* Write the buf to file.
   return the number of written bytes. */
int write(int fd, const void *buf, unsigned size){


  if(!is_user_vaddr(buf) || buf == NULL || pagedir_get_page(thread_current()->pagedir,buf) == NULL ){
	exit(-1);
  }

  if(fd == 1){  // stdout
	putbuf(buf,size);
	return size;
  }
  else if(fd == 0 || fd > thread_current()->max_fd  || fd < 0){
	return -1;
  }
  else{
	lock_acquire(&filesys_lock);
          struct file *f = thread_current()->fd[fd];
	  if(f != NULL ){
		 return -1;
	  }
          int write_len = (f != NULL) ? file_write(f,buf,size) : -1;
	lock_release(&filesys_lock);

	return write_len;
  }
}


/* Move the pointer in open file to specific position. */
void seek(int fd, unsigned position){
  if(fd > thread_current()->max_fd) return;
  struct file *f = thread_current()->fd[fd];
  if(f!=NULL){
    lock_acquire(&filesys_lock);
    file_seek(f,position);
    lock_release(&filesys_lock);
  }
}


/* Return the position of pointer in open file. */
unsigned tell(int fd){
  if(fd > thread_current()->max_fd) return 0;
  struct file *f = thread_current()->fd[fd];
  lock_acquire(&filesys_lock);
  int result = (f != NULL) ? file_tell(f) : 0;
  lock_release(&filesys_lock);

  return result;
}


/* Close specific file desciptor. */
void close(int fd){
  if(fd > thread_current()->max_fd) return;
  struct file *f = thread_current()->fd[fd];
  #ifdef DEBUG
  #endif
  if(f == NULL || fd  < 3 ){
	 return;
  }

  thread_current()->fd[fd] = NULL; // makes NULL
  lock_acquire(&filesys_lock);
  file_close(f);
  lock_release(&filesys_lock);
}




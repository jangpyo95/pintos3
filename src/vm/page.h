#ifndef VM_PAGE_H
#define VM_PAGE_H

#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "userprog/process.h"
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
#include "threads/synch.h"

//#define MAX_STACK_SIZE (1 << 23)
//#define STACK_INDICATOR 0xbfff7f80

struct vm_entry
{
	// list
	struct list_elem elem;

	// for load_file_to_page_table
	struct file * file;
	off_t ofs;
	void * upage;
	uint32_t read_bytes;
	uint32_t zero_bytes;
	bool writable;
	bool is_in_memory;

	struct thread *owner;

	size_t swap_index;

	// type
	uint8_t  type; //0 = VM_BIN, 1=VM_FILE, 2=VM_ANON


};


void vm_destroy(struct thread * cur);
struct vm_entry* find_vme(void *vaddr);
bool load_file (void *kaddr, struct vm_entry *vme);


#endif /* vm/page.h */

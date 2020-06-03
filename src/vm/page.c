#include "vm/page.h"

#include "userprog/process.h"
#include "userprog/syscall.h"


//all added in lab3
// clear the vm list  and reference of a thread
void
vm_destroy(struct thread * cur)
{
	struct list *vm_list =&cur->vm;
	struct list_elem * e;

	for (e = list_begin(vm_list); e != list_end(vm_list); e = list_next(e))
	{
		//struct vm_entry* ve= list_entry(e, struct vm_entry, elem);
		list_remove(e);
	}
}

/* Search vm_entry corresponding to vaddr in the address space of the current process */
struct vm_entry* find_vme(void *vaddr){
	struct thread* cur = thread_current();
	struct list* vm = &cur->vm;
	void* upage = pg_round_down(vaddr);
//loop to find matching vm entry
	struct list_elem *e;
	for(e = list_begin (vm); e != list_end(vm); e = list_next(e)){
		struct vm_entry * vment = list_entry(e, struct vm_entry, elem);
		if(vment->upage==upage){
			return vment;
		}
	}
	//not found
	return NULL;
}

bool load_file (void *kaddr, struct vm_entry *vme)
{
/* Use file_read_at() or file_read() + file_seek() */
/* Write physical memory as much as read_bytes by file_read_at*/
/* Return file_read_at status*/ 	
/* Pad 0 as much as zero_bytes*/
/* if file is loaded to memory, return true */

//set the flag to PAL_ZERO to set all the data to 0 in the page. 
//enum palloc_flags flag = PAL_USER|PAL_ZERO; 
//get a page and save the pointer to that page
//uint8_t * page_pointer = palloc_get_page(flag);
//if failed to allocate, return false
//if(page_pointer == NULL){
//	return false;
//}

//if the addr is NULL return false.
if(kaddr == NULL){
	return false;
}
if (vme-> read_bytes != 0){
	//set the offset of the file to read
	file_seek(vme->file, vme->ofs);
	//if not read fully(insufficient memory or error), return false and free the page
	if(file_read(vme->file,kaddr, vme->read_bytes) != (off_t)vme->read_bytes){
		palloc_free_page(kaddr);
		return false;
	} 
	//padding shd be unnecessary due to PAL_ZERO
	memset (kaddr + vme->read_bytes, 0, vme->zero_bytes);
}
 
return true;
}

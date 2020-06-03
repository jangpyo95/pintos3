#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H
#include <user/syscall.h>
#include "devices/shutdown.h"

struct lock filesys_lock;
struct lock load_lock;

void syscall_init (void);

void halt(void);

void exit(int status);

pid_t exec(const char *cmd_line);

int wait(pid_t pid);

bool create(const char *file , unsigned initial_size);

bool remove(const char *file);

int open(const char *file);

int filesize(int fd);

int read(int fd, void *buffer, unsigned size);

int write(int fd, const void *buffer, unsigned size);

void seek(int fd, unsigned position);

unsigned tell(int fd);

void close(int fd);

void release_filesyslock(void);

#endif /* userprog/syscall.h */


bool chdir(const char *);

bool mkdir(const char *);

bool readdir(int , char*);

bool isdir(int);

int inumber(int);






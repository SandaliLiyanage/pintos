#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H


#include "threads/synch.h"
#include "filesys/file.h"

void syscall_init (void);

struct lock file_system_lock;

/*Returns a nonnegative integer handle called a "file descriptor"
(fd), or -1 if the file could not be opened.
File descriptors numbered 0 and 1 are reserved for the console*/
struct file_descriptor {
  struct file *file;
  int Fd;
  struct list_elem fd_elem;    
};

void syscall_init(void);

#endif /* userprog/syscall.h */

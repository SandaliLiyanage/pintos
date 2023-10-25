#include "userprog/syscall.h"
#include "userprog/pagedir.h"
#include "userprog/process.h"
#include <stdio.h>
#include <syscall-nr.h>
#include <list.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/synch.h"
#include "threads/malloc.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "devices/shutdown.h"
#include "devices/input.h"


#define CONSOLE_OUTPUT 1
#define KEYBOARD_INPUT 0
#define ERROR_STATUS -1
#define SUCCESS_STATUS 0

// void validate_ptr(const void *_ptr);


static void syscall_handler (struct intr_frame * UNUSED);

static void syscall_exit(int status);
static int syscall_write(int fd, const void *buffer, unsigned size);

struct file_descriptor *get_from_fd(int fd);

void
syscall_init (void) 
{
  lock_init(&file_system_lock);
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f ) 
{
  //first check if f->esp is a valid pointer)
  validate_ptr(f->esp);
  int sys_type = *(int*)f->esp;


  //cast f->esp into an int*, then dereference it for the SYS_CODE

  switch(*(int*) f->esp){

    /*Terminates Pintos by calling shutdown_power_off()*/
    case SYS_HALT:
    {
      shutdown_power_off();
      break;
    }
    /*Terminates the current user program, returning status to the kernel.status of 0
    indicates success and nonzero values indicate errors*/
    case SYS_EXIT:{
      int status = *((int*)f->esp + 1);
      syscall_exit(status);
      break;
    }
    
    case SYS_WRITE:
    {
      
      int fd = *((int*)f->esp + 1);
      void* buffer = (void*)(*((int*)f->esp + 2));
      unsigned size = *((unsigned*)f->esp + 3);
      //the return value should be stored in f->eax
      int eax = syscall_write(fd, buffer, size);	
      break;
    }
    
    default:
    {
      printf("Invalid system call!\n");
      thread_exit();
      break;
    }
  }

  printf ("system call!\n");
  thread_exit ();
}

static int syscall_write(int fd, const void *buffer, unsigned size)
{
  struct file_descriptor *_file_descriptor;
  char *_buffer = (char *)buffer;
  int written_size = 0;

  if (fd == CONSOLE_OUTPUT)
  {
    putbuf(_buffer, size);
    written_size = size;    
  }
  else if (fd == KEYBOARD_INPUT)
  {
    return ERROR_STATUS;
  }
  else
  {
    _file_descriptor = get_from_fd(fd);
    if (_file_descriptor == NULL)
    {
      return ERROR_STATUS;
    }

    lock_acquire((&file_system_lock));
    written_size = file_write(_file_descriptor->file, _buffer, size);
    lock_release(&file_system_lock);
  }

  return written_size;
}

void syscall_exit(int status)
{
  struct thread *cur = thread_current();
  cur -> exit_status = status;       //, a status of 0 indicates success and nonzero values indicate errors
  if(cur -> status == SUCCESS_STATUS){
    printf("%s: exit successful", cur->name);

  }
  else{
    printf("exit not successful");
  }
  thread_exit();
}


struct file_descriptor *get_from_fd(int fd)
{
  struct thread *curr_t = thread_current();
  struct file_descriptor *_file_descriptor;
  struct list_elem *fd_elem;

  // Check if child_tid is in current threads children.
  for (
      fd_elem = list_begin(&curr_t->open_fd_list);
      fd_elem != list_end(&curr_t->open_fd_list);
      fd_elem = list_next(fd_elem))
  {
    _file_descriptor = list_entry(fd_elem, struct file_descriptor, fd_elem);
    if (_file_descriptor->Fd == fd)
    {
      break;
    }
  }
  // If fd was not in list return NULL
  if (fd_elem == list_end(&curr_t->open_fd_list))
  {
    return NULL;
  }

  return _file_descriptor;
}
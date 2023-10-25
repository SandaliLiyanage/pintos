  +-----------------+
                         |      CS 140     |
                         |  SAMPLE PROJECT |
                         | DESIGN DOCUMENT |
                         +-----------------+

210344U  LiyanagePLDSK.21

---- PRELIMINARIES ----

>> Please cite any offline or online sources you consulted while
>> preparing your submission, other than the Pintos documentation,
>> course text, and lecture notes.

CSCI 350: Pintos Guide   Written by: Stephen Tsung-Han Sher


                                 JOIN
                                 ====

1. Argument Passing

---- DATA STRUCTURES ----

>> Copy here the declaration of each new or changed `struct' or `struct'
>> member, global or static variable, `typedef', or enumeration.
>> Identify the purpose of each in 25 words or less.

changed the following functions in process.c

-> static void start_process (void *file_name_)
-> bool load (const char *file_name, void (**eip) (void), void **esp)  
-> static bool setup_stack (void **esp, const char* args) 
	added additional argument to the setup_stack to pass the raw file_name which consists additional arguments, to the function

>> Describe how you implemented argument parsing.  
>> How do you arrange for the elements in the right order in the stack

-> Argument parsing is done in the function setup_stack. Process_execute takes space seperated arguments as file_name and it is passed into the `start_process`. Start_process calls `load` function and the  `load` calls the function setup_stack.

-> Argument parsing was implemented mainly using the `strtok_r` function. It was mainly used to separate the executable file name and the other arguments from the raw file name that we get as an input to the processs execute. We first parse the arguments deliminating by the white spaces and store them in an array

-> Then write each argument including the executable file name in reverse order to the stack. We use the function `memcpy` for this.

-> Write the necessary number of 0s to word-align to 4 bytes

-> store the addresses pointing to each argument to another list called args_addr_array


>>In Pintos, the kernel separates commands into a executable name and >>arguments. 
>>In Unix like systems, the shell does this separation. What are the advantages of the unix approach.

2. System Calls

---- DATA STRUCTURES ----

>> Copy here the declaration of each new or changed `struct' or `struct'
>> member, global or static variable, `typedef', or enumeration.
>> Identify the purpose of each in 25 words or less.

The following strures were changed in the files.

  In thread.h
    `thread`
    struct thread
      {
        /* Owned by thread.c. */
        tid_t tid;                          /* Thread identifier. */
        enum thread_status status;          /* Thread state. */
        char name[16];                      /* Name (for debugging purposes). */
        uint8_t *stack;                     /* Saved stack pointer. */
        int priority;                       /* Priority. */
        struct list_elem allelem;           /* List element for all threads list. */
        int exit_status;                    /* Exit status of thread. */

        struct list open_fd_list; 
        /* Shared between thread.c and synch.c. */
        struct list_elem elem;              /* List element. */

      }

  In system.h
    `file_descripter`and `file_system_lock`
    struct file_descriptor {
      struct file *file;
      int Fd;
      struct list_elem fd_elem;    
    };

    struct lock file_system_lock;


>> Describe your code for reading and writing user data from the kernel.

When processing user data,  different functions are used based on the input or output type. If we're dealing with keyboard inputs from STDIN, we utilize the input_getc function to read characters. Conversely, if we're working with file data, we obtain the appropriate file pointer from the file descriptor and employ the file_read function to read from the file.

When writing user data, To write data to STDOUT, we use the putbuf function. If we're writing to a file, we first obtain the corresponding file pointer from the file descriptor and then use the file_write function to write to the file.

A "latch" is a new synchronization primitive.  Acquires block
until the first release.  Afterward, all ongoing and future
acquires pass immediately.

    /* Latch. */
    struct latch 
      {
        bool released;              /* Released yet? */
        struct lock monitor_lock;   /* Monitor lock. */
        struct condition rel_cond;  /* Signaled when released. */
      };

Added to struct thread:

    /* Members for implementing thread_join(). */
    struct latch ready_to_die;   /* Release when thread about to die. */
    struct semaphore can_die;    /* Up when thread allowed to die. */
    struct list children;        /* List of child threads. */
    list_elem children_elem;     /* Element of `children' list. */

---- ALGORITHMS ----

>> Briefly describe your implementation of thread_join() and how it
>> interacts with thread termination.

thread_join() finds the joined child on the thread's list of
children and waits for the child to exit by acquiring the child's
ready_to_die latch.  When thread_exit() is called, the thread
releases its ready_to_die latch, allowing the parent to continue.

---- SYNCHRONIZATION ----

>> Consider parent thread P with child thread C.  How do you ensure
>> proper synchronization and avoid race conditions when P calls wait(C)
>> before C exits?  After C exits?  How do you ensure that all resources
>> are freed in each case?  How about when P terminates without waiting,
>> before C exits?  After C exits?  Are there any special cases?

C waits in thread_exit() for P to die before it finishes its own
exit, using the can_die semaphore "down"ed by C and "up"ed by P as
it exits.  Regardless of whether whether C has terminated, there
is no race on wait(C), because C waits for P's permission before
it frees itself.

Regardless of whether P waits for C, P still "up"s C's can_die
semaphore when P dies, so C will always be freed.  (However,
freeing C's resources is delayed until P's death.)

The initial thread is a special case because it has no parent to
wait for it or to "up" its can_die semaphore.  Therefore, its
can_die semaphore is initialized to 1.

---- RATIONALE ----

>> Critique your design, pointing out advantages and disadvantages in
>> your design choices.

This design has the advantage of simplicity.  Encapsulating most
of the synchronization logic into a new "latch" structure
abstracts what little complexity there is into a separate layer,
making the design easier to reason about.  Also, all the new data
members are in `struct thread', with no need for any extra dynamic
allocation, etc., that would require extra management code.

On the other hand, this design is wasteful in that a child thread
cannot free itself before its parent has terminated.  A parent
thread that creates a large number of short-lived child threads
could unnecessarily exhaust kernel memory.  This is probably
acceptable for implementing kernel threads, but it may be a bad
idea for use with user processes because of the larger number of
resources that user processes tend to own.
[ << ]	[ >> ]	 	 	 	 	 	[Top]	[Contents]	[Index]	[ ? ]

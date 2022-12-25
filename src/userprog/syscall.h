#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H
#include "lib/user/syscall.h" // 미리 정의된 구조체 사용을 위해 include

void syscall_init (void);
/* 추가 함수 prototype*/
void is_useradd(const void* vaddr);
void halt (void);
void exit (int status);
pid_t exec (const char *cmd_line);
int wait (pid_t pid);
bool create (const char *file, unsigned initial_size);
bool remove (const char *file);
int open (const char *file);
int filesize (int fd);
int read (int fd, void *buffer, unsigned size);
int write (int fd, const void *buffer, unsigned size);
void seek (int fd, unsigned position);
unsigned tell (int fd);
void close (int fd);
int fibonacci(int n);
int max_of_four_int(int a, int b, int c, int d);
bool isdir(int fd);


#endif /* userprog/syscall.h */

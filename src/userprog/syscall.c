#include "userprog/syscall.h"
#include <stdio.h>
#include <string.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "devices/shutdown.h"
#include "threads/vaddr.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "threads/synch.h"

static void syscall_handler (struct intr_frame *);
struct lock file_;

struct file 
  {
    struct inode *inode;        /* File's inode. */
    off_t pos;                  /* Current position. */
    bool deny_write;            /* Has file_deny_write() been called? */
  };
void
syscall_init (void) 
{
  lock_init(&file_); //file의 lock
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}
/* esp의 값이 user address인지 판별*/
void is_useradd(const void *vaddr)
{
  if(!is_user_vaddr(vaddr))
    exit(-1);
}
static void
syscall_handler (struct intr_frame *f ) 
{
  //printf("syscall number:%d", *(uint32_t*)f->esp);
  //printf("\n%d %d %d %d is in (f->esp)\n", *(uint32_t*)(f->esp),*(uint32_t*)(f->esp+4),*(uint32_t*)(f->esp+8),*(uint32_t*)(f->esp+12));
  //printf ("system call!\n");
  //hex_dump(f->esp, f->esp, 100,1);

  switch (*(uint32_t*)(f->esp)){
    case SYS_HALT:
      //is_useradd(f->esp+4);
      halt();
      break;
    case SYS_EXIT:
      is_useradd(f->esp+4);
      exit(*(uint32_t*)(f->esp+4));
      break;
    case SYS_EXEC:
      //printf("\ncmd: %d\n", (const char*)(f->esp+20));
      is_useradd(f->esp+4);
      f->eax = exec((const char*)*(uint32_t*)(f->esp+4));
      break;
    case SYS_WAIT:
      is_useradd(f->esp+4);
      f->eax = wait((pid_t)*(uint32_t*)(f->esp+4));
      break;
    case SYS_READ:
      is_useradd(f->esp+4);
      is_useradd(f->esp+8);
      is_useradd(f->esp+12);
      f->eax = read((int)*(uint32_t*)(f->esp+4), (const void*)*(uint32_t*)(f->esp+8),(unsigned)*(uint32_t*)(f->esp+12));
      break;
    case SYS_WRITE:
    //printf("Write!\n");
      is_useradd(f->esp+4);
      is_useradd(f->esp+8);
      is_useradd(f->esp+12);
      f->eax = write((int)*(uint32_t*)(f->esp+4), (const void*)*(uint32_t*)(f->esp+8),(unsigned)*(uint32_t*)(f->esp+12));
      break;
    case SYS_FIBO:
      is_useradd(f->esp+4);
      f->eax = (uint32_t)fibonacci((int)*(uint32_t*)(f->esp+4));
      break;
    case SYS_MAX_FOUR:
      is_useradd(f->esp+4);
      is_useradd(f->esp+8);
      is_useradd(f->esp+12);
      is_useradd(f->esp+16);
      f->eax = max_of_four_int((int)*(uint32_t*)(f->esp+4),(int)*(uint32_t*)(f->esp+8),(int)*(uint32_t*)(f->esp+12),(int)*(uint32_t*)(f->esp+16));
      break;
    case SYS_CREATE:
      is_useradd(f->esp+4);
      is_useradd(f->esp+8);
      f->eax = create((const char*)*(uint32_t*)(f->esp+4), (unsigned)*(uint32_t*)(f->esp+8));
      break;
    case SYS_REMOVE:
      is_useradd(f->esp+4);
      f->eax = remove((const char*)*(uint32_t*)(f->esp+4));
      break;
    case SYS_OPEN:
      is_useradd(f->esp+4);
      f->eax = open((const char*)*(uint32_t*)(f->esp+4));
      break;
    case SYS_CLOSE:
      is_useradd(f->esp+4);
      close((int)*(uint32_t*)(f->esp+4));
      break;
    case SYS_FILESIZE:
      is_useradd(f->esp+4);
      f->eax = filesize((int)*(uint32_t*)(f->esp+4));
      break;
    case SYS_SEEK:
      is_useradd(f->esp+4);
      is_useradd(f->esp+8);
      seek((int)*(uint32_t*)(f->esp+4), (unsigned)*(uint32_t*)(f->esp+8));
      break;
    case SYS_TELL:
      is_useradd(f->esp+4);
      f->eax = tell((int)*(uint32_t*)(f->esp+4));
      break;
    case SYS_ISDIR:
      is_user_vaddr(f->esp+4);
      f->eax = isdir((int)*(uint32_t*)(f->esp+4));
      break;
    case SYS_CHDIR:
      is_useradd(f->esp+4);
      f->eax = chdir((const char*)*(uint32_t*)(f->esp+4));
      break;
    case SYS_MKDIR:
      is_useradd(f->esp+4);
      f->eax = mkdir((const char*)*(uint32_t*)(f->esp+4));
      break;
    case SYS_READDIR:
      is_useradd(f->esp+4);
      is_useradd(f->esp+8);
      f->eax = readdir((int)*(uint32_t*)(f->esp+4),(char*)*(uint32_t*)(f->esp+8));
      break;
    case SYS_INUMBER:
      is_user_vaddr(f->esp+4);
      f->eax = inumber((int)*(uint32_t*)(f->esp+4));
      break;

  }
}
void halt(void){
  shutdown_power_off();
}
void exit (int status)
{
  
  printf("%s: exit(%d)\n", thread_name(), status);
  thread_current() -> exit_stat = status;
  for(int i=3; i<128;i++){
    // exit하기전에 열려있는 file을 닫는다.
    if(thread_current()->fd[i] != NULL)
    {
      close(i);
    }
  }
  thread_exit();
}
pid_t exec (const char *cmd_line){
  
 // lock_acquire(&file_);
  //printf("executing.. %s\n", thread_name());
  pid_t pid = (pid_t)process_execute(cmd_line);
  //lock_release(&file_);
  return pid;
}
int wait (pid_t pid)
{
  //printf("waiting...\n");
  return process_wait((tid_t)pid);
}
int read (int fd, void *buffer, unsigned size){
  int bytes_read = -1; // -1 if error
  
  if(buffer == NULL)
  {
    exit(-1);
  }
  lock_acquire(&file_);
  is_useradd(buffer);
  if(!fd){
    bytes_read=0;
    while(input_getc()!='\0'){
      bytes_read++;
    }
  }
  else if(fd >2)
  { 
    if(thread_current()->fd[fd] == NULL)
    {
      lock_release(&file_);
      exit(-1);
    }
    bytes_read = file_read(thread_current()->fd[fd], buffer, size);
  }
  lock_release(&file_);
  return bytes_read;
}
int write(int fd, const void *buffer, unsigned size)
{
  int return_val;
  //printf("\nWrite\n");
  struct inode *inode;
  if(buffer == NULL)
  {
    exit(-1);
  }
  lock_acquire(&file_);
  is_useradd(buffer);
  if(fd == 1){
    putbuf(buffer, size);
    lock_release(&file_);
    return size;
  }
  else if(fd >2)
  {
    if(thread_current()->fd[fd] == NULL)
    {
      lock_release(&file_);
      exit(-1);
    }
    //쓰려는 파일이 dir인경우
    inode = file_get_inode(thread_current()->fd[fd]);
    if(inode_isdir(inode)){
      lock_release(&file_);
      exit(-1);
    }

    if(thread_current()->fd[fd]->deny_write)
    {
      //printf("\ndenied!\n");
      file_deny_write(thread_current()->fd[fd]);
    }
    return_val = file_write(thread_current()->fd[fd], buffer, size);
    lock_release(&file_);
    return return_val;
  }
 lock_release(&file_);
  return -1;
}
bool create (const char *file, unsigned initial_size){
  bool return_val;
  if(file == NULL){
    exit(-1);
  }
  //lock_acquire(&file_);
  return_val = filesys_create(file, initial_size);
  //lock_release(&file_);
  return return_val;
}
bool remove (const char *file){
  bool return_val;
  if(file == NULL){
    exit(-1);
  }
  //lock_acquire(&file_);
  return_val = filesys_remove(file);
  //lock_release(&file_);
  return return_val;
}
int open (const char *file)
{
  if(file == NULL){
    exit(-1);
  }
  
  is_useradd(file);
  lock_acquire(&file_);
  struct file *f = filesys_open(file);
  if(f == NULL)
  {
    lock_release(&file_);
    return -1;
  }
   
  for(int i=3; i<128; i++)
  {
    // fd 0,1,2는 이미 할당되어 있으므로 3부터 빈 곳을 찾는다
    if(thread_current()->fd[i] == NULL)
    {
      // 이미 열려있는 파일, 즉 현재 thread이름과 일치하면 쓰기를 방지
      //printf("\nfilename: %s, thread name: %s\n", file, thread_current()->name);
      if(strcmp(thread_current()->name,file)==0)
      {
        //printf("\ndeny wirte, %s\n\n", thread_current()->name);
        file_deny_write(f);
      }
      thread_current()->fd[i] = f; 
      lock_release(&file_);
      return i;
    }
    
  }
  lock_release(&file_);
  return -1;

}
int filesize (int fd){
  if(thread_current()->fd[fd] == NULL)
  {
    exit(-1);
  }
 
  int size = file_length(thread_current()->fd[fd]);
  
  return size;
}
void seek (int fd, unsigned position)
{
  if(thread_current()->fd[fd] == NULL)
  {
    exit(-1);
  }
  //lock_acquire(&file_);
  file_seek(thread_current()->fd[fd], position);
  //lock_release(&file_);
}
unsigned tell (int fd)
{
  unsigned return_val;
  if(thread_current()->fd[fd] == NULL)
  {
    exit(-1);
  }
  //lock_acquire(&file_);
  return_val = file_tell(thread_current()->fd[fd]);
  //lock_release(&file_);
  return return_val;
}
void close (int fd)
{
  if(thread_current()->fd[fd] == NULL)
  {
    exit(-1);
  }
  //lock_acquire(&file_);
  file_close(thread_current()->fd[fd]);
  thread_current()->fd[fd] = NULL;
  //lock_release(&file_);

}

bool isdir(int fd){
  
  if(thread_current()->fd[fd]==NULL){
    return false;
  }
  return inode_isdir(file_get_inode(thread_current()->fd[fd]));

}

bool chdir(const char *dir){

  struct file *f = filesys_open(dir);
  struct inode *inode;

  //주어진 문자열이 긴 경로일 경우
  if(dir_lookup(thread_current()->dir, dir, &inode)){
    dir_close(thread_current()->dir);
    thread_current()->dir = dir_open(inode);
    return true;
  }
  else if(f  != NULL){
    //하나의 directory일 경우
    dir_close(thread_current()->dir);
    thread_current()->dir = dir_open(file_get_inode(f));
    return true;
  }
  return false;
}

bool mkdir(const char *dir){

  //유효하지 않은 dir 이름
  //printf("dir = %s\n", dir);
  if(dir == NULL ||strlen(dir)==0){
    return false;
  }
  return filesys_mkdir(dir);
}

bool readdir(int fd, char *name){

  struct file *f = thread_current()->fd[fd];
  if(f == NULL){
    return false;
  }
  struct inode *inode = file_get_inode(f);
  if(!inode_isdir(inode)){
    //dir이 아니라면
    return false;
  }
  //struct dir *dir = dir_open(inode);
  struct dir *dir = (struct dir *)f;
  bool res = dir_readdir(dir, name);
  if(!dir) return false;

  // .과 .. 제외
  while(strcmp(name, ".") == 0 || strcmp(name, "..") == 0){
    if(res == false) break;
    res = dir_readdir(dir, name);
  }
  return res;

}

int inumber(int fd){

  struct file *f = thread_current()->fd[fd];
  if(f == NULL) return -1;
  return get_inumber(file_get_inode(f));
}
int fibonacci(int n)
{
  int prev = 0;
  int cur = 1;
  int result=0;
  
  if(n < 0)
  {
     return -1; 
  }
  else if(n == 0)
  {
    return 0;
  }
  else if(n == 1 || n == 2)
  {
    return cur;
  }
  else{
    for(int i = 3; i <= n+1; i++)
    {
      result = prev + cur;
      prev = cur;
      cur = result;
    }
    
    return result;
  }
}
int max_of_four_int(int a, int b, int c, int d)
{
  int max = a;
  if (max < b)
  {
    max=b;
  }
  if(max < c)
  {
    max = c;
  }
  if(max <d)
  {
    max = d;
  }
  return max;
}
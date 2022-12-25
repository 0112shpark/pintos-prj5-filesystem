#include "filesys/filesys.h"
#include <debug.h>
#include <stdio.h>
#include <string.h>
#include "filesys/file.h"
#include "filesys/free-map.h"
#include "filesys/inode.h"
#include "filesys/directory.h"
#include "filesys/cache.h"
#include "threads/thread.h"
#include "filesys/inode.h"

/* Partition that contains the file system. */
struct block *fs_device;

static void do_format (void);

/* Initializes the file system module.
   If FORMAT is true, reformats the file system. */
void
filesys_init (bool format) 
{
  fs_device = block_get_role (BLOCK_FILESYS);
  if (fs_device == NULL)
    PANIC ("No file system device found, can't initialize file system.");

  buffer_cache_init();
  inode_init ();
  free_map_init ();

  if (format) 
    do_format ();

  free_map_open ();
  thread_current()->dir = dir_open_root();
}

/* Shuts down the file system module, writing any unwritten data
   to disk. */
void
filesys_done (void) 
{
  buffer_cache_terminate();
  free_map_close ();
}

/* Creates a file named NAME with the given INITIAL_SIZE.
   Returns true if successful, false otherwise.
   Fails if a file named NAME already exists,
   or if internal memory allocation fails. */
bool
filesys_create (const char *name, off_t initial_size) 
{
  //파일 이름을 저장할 변수
  char file[strlen(name)+1];
  block_sector_t inode_sector = 0;
  struct dir *dir = get_path(name, file);

  //유효하지 않은 dir
  if(dir != NULL && is_removed(dir_get_inode(dir))){
    dir_close(dir);
    return false;
  }  
  bool success = (dir != NULL
                  && free_map_allocate (1, &inode_sector)
                  && inode_sector <4095
                  && inode_create (inode_sector, initial_size,0)
                  && dir_add (dir, file, inode_sector));
  if (!success && inode_sector != 0) 
    free_map_release (inode_sector, 1);
  dir_close (dir);

  return success;
}


/* Opens the file with the given NAME.
   Returns the new file if successful or a null pointer
   otherwise.
   Fails if no file named NAME exists,
   or if an internal memory allocation fails. */
struct file *
filesys_open (const char *name)
{
  
  char file[strlen(name)+1];
  struct dir *dir = get_path(name, file);
  struct inode *inode = NULL;
  struct inode *temp = dir_get_inode(dir);
  

  //유효하지 않은 inode
  if(dir != NULL && is_removed(temp)){
    dir_close(dir);
    return NULL;
  }
  if (dir != NULL)
    dir_lookup (dir, file, &inode);
  dir_close (dir);

  return file_open (inode);
}

/* Deletes the file named NAME.
   Returns true if successful, false on failure.
   Fails if no file named NAME exists,
   or if an internal memory allocation fails. */
bool
filesys_remove (const char *name) 
{
  char file[strlen(name)+1];
  struct dir *dir = get_path(name, file);

  struct inode *inode;
  //dir 검색
  dir_lookup(dir, file, &inode);

  struct dir *isdir = NULL;
  char temp[strlen(name)+1];
  //dir이 아니거나 dir이면 존재하는지 dir인지 확인
  bool success = false;
  if(!inode_isdir(inode)||((isdir = dir_open(inode)) && ! dir_readdir(isdir, temp))){
     success = dir != NULL && dir_remove (dir, file);
  }
  dir_close (dir); 
  
  if(isdir){
    dir_close(isdir);
  }
  return success;
}

/* Formats the file system. */
static void
do_format (void)
{

  struct dir *root_dir = dir_open_root();
  //struct inode *root_inode = dir_get_inode(root_dir);
  
  printf ("Formatting file system...");
  free_map_create ();
  if (!dir_create (ROOT_DIR_SECTOR, 16))
    PANIC ("root directory creation failed");
  
  // .과 ..dir 만들기
  dir_add(root_dir, ".", ROOT_DIR_SECTOR);
  dir_add(root_dir, "..", ROOT_DIR_SECTOR);
  free_map_close ();
  printf ("done.\n");
}

//input을 절대경로, 상대경로로 parse
struct dir* get_path(char *name, char* file){

  struct dir *dir = NULL;
  struct inode *inode;
  char *token;
  char *nextToken;
  char *temp;

  //error handling
  if(!name || !file || strlen(name) == 0 ){
    return NULL;
  }

  char copy_name[strlen(name)+1];
  strlcpy(copy_name, name, strlen(name)+1);
  //printf("parsing\n");
  //절대경로
  if(copy_name[0] == '/'){
    dir = dir_open_root();
  }
  else 
    dir = dir_reopen(thread_current()->dir);
  
  // /로 parsing
  token = strtok_r(copy_name, "/", &temp);
  nextToken = strtok_r(NULL, "/", &temp);

  // /가 없을때 까지 parsing
  while(token && nextToken){
    
    inode = NULL;
    //dir이 아닐경우
    if(!dir_lookup(dir, token, &inode)){
      dir_close(dir);
      return NULL;
    }
    // dir inode가 아닐경우
    if(!inode_isdir(inode)){
      dir_close(dir);
      return NULL;
    }
    dir_close(dir);
    dir = dir_open(inode);
    token = nextToken;
    nextToken = strtok_r(NULL, "/", &temp);
  }
  //마지막은 file이름, file이름 저장
  if(token){
    strlcpy(file, token, strlen(token)+1);
  }
  else{
    //파일이 /로끝남->마지막 dir return
    strlcpy(file, ".", 2);
  }
  return dir;

}

bool filesys_mkdir(const char* name){


  //printf("%s\n", name);
  if(name == NULL){
    return false;
  }
  char file[strlen(name)+1];
  struct inode *inode;
  struct dir* dir = get_path(name, file);
  //printf("D\n");
  //같은 이름이 존재하면 실패
  if(dir_lookup(dir, file, &inode)){
    return false;
  }
  //printf("dd\n");
  block_sector_t inode_sector;


  bool success = (dir != NULL
                  && free_map_allocate (1, &inode_sector)
                  && dir_create (inode_sector, 16)
                  && dir_add (dir, file, inode_sector));
  if (!success && inode_sector != 0) 
    free_map_release (inode_sector, 1);
  //printf("2\n");
  if(success){
    struct dir *dot_dir = dir_open(inode_open(inode_sector));

    if(!dir_add (dot_dir, ".", inode_sector)){
      return false;
    }
    if(!dir_add(dot_dir, "..", get_inumber(dir_get_inode(dir)))){
      return false;
    }
    dir_close(dot_dir);
  }
  dir_close(dir);
  return success;
}
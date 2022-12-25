#include "filesys/inode.h"
#include <list.h>
#include <debug.h>
#include <round.h>
#include <string.h>
#include "filesys/filesys.h"
#include "filesys/free-map.h"
#include "threads/malloc.h"
#include "filesys/cache.h"

/* Identifies an inode. */
#define INODE_MAGIC 0x494e4f44

//inode의 크기가 block_sector_size와 동일하게
#define DIRECT_BLOCK 123
#define INDIRECT_BLOCK (BLOCK_SECTOR_SIZE / sizeof(block_sector_t))

/* On-disk inode.
   Must be exactly BLOCK_SECTOR_SIZE bytes long. */
struct inode_disk
  {
    block_sector_t direct_map[DIRECT_BLOCK];               /* direct inodes map */
    block_sector_t indirect_map;
    block_sector_t double_indirect_map;
    //block_sector_t start;
    int is_dir;                         /*0: no, 1: yes*/
    off_t length;                       /* File size in bytes. */
    unsigned magic;                     /* Magic number. */
    
  };



/* 계층구조 표현*/
struct sector_level{
  int level; // 0: direct, 1: indirect, 2: double direct, -1, error
  off_t single_add; // direct, indirect addr
  off_t double_add; // double indirect addr
};

// indirect block map
struct indirect_block{
  block_sector_t map_arr[INDIRECT_BLOCK];
};
/* In-memory inode. */
struct inode 
{
  struct list_elem elem;              /* Element in inode list. */
  block_sector_t sector;              /* Sector number of disk location. */
  int open_cnt;                       /* Number of openers. */
  bool removed;                       /* True if deleted, false otherwise. */
  int deny_write_cnt;                 /* 0: writes ok, >0: deny writes. */
  struct lock inode_lock;
};


static void find_lev(off_t pos, struct sector_level *sec_lev);
static bool update_inode(struct inode_disk * inode_disk, block_sector_t new_sector, struct sector_level sec_lev);
static inline off_t off_to_byte(int off);
bool update_inode_length(struct inode_disk* inode_disk, off_t start, off_t end);
static void free_inode(struct inode_disk *inode_disk);

/* Returns the number of sectors to allocate for an inode SIZE
   bytes long. */
static inline size_t
bytes_to_sectors (off_t size)
{
  return DIV_ROUND_UP (size, BLOCK_SECTOR_SIZE);
}
/* Returns the block device sector that contains byte offset POS
   within INODE.
   Returns -1 if INODE does not contain data for a byte at offset
   POS. */
static block_sector_t
byte_to_sector (const struct inode_disk *inode_disk, off_t pos) 
{


  ASSERT (inode_disk != NULL);

  if(pos>inode_disk->length)
    return 0;
  block_sector_t res;
  struct indirect_block *indirect;
  struct indirect_block *double_indirect;
  //block의 종류
  struct sector_level sec_lev;  
  //종류 찾기
  find_lev(pos, &sec_lev);
  
  //에러값으로 초기화
  res = 0;

  if(sec_lev.level == 0){
    //direct
    res = inode_disk->direct_map[sec_lev.single_add];
  }
  else if(sec_lev.level == 1){
    //indirect
    indirect = (struct indirect_block*)calloc (1, BLOCK_SECTOR_SIZE);
    
    //block에서 읽기&채우기
    if(indirect){
      buffer_cache_read(inode_disk->indirect_map, (void*)indirect, 0, BLOCK_SECTOR_SIZE,0);
      res = indirect->map_arr[sec_lev.single_add];
    }
    else
      res = 0;
    free(indirect);
  }
  else if(sec_lev.level == 2){
    //double indirect
    indirect = (struct indirect_block*)calloc (1, BLOCK_SECTOR_SIZE);
    double_indirect = (struct indirect_block*)calloc (1, BLOCK_SECTOR_SIZE);

    //block에서 읽기&채우기
    if(indirect && double_indirect){
      buffer_cache_read(inode_disk->double_indirect_map, (void*)indirect, 0, BLOCK_SECTOR_SIZE,0);
      buffer_cache_read(indirect->map_arr[sec_lev.single_add], (void*)double_indirect, 0, BLOCK_SECTOR_SIZE,0);
      res = double_indirect->map_arr[sec_lev.double_add];
    }
    else
      res = 0;
    free(indirect);
    free(double_indirect);
  }
  return res;

}

/* block의 level을 찾고 할당된 sector를 찾는다*/
static void find_lev(off_t pos, struct sector_level *sec_lev){
  
  //에러값 미리 설정
  sec_lev->level = -1;

  // byte를 block단위로 변환
  off_t sec_pos = pos / BLOCK_SECTOR_SIZE;

  if(sec_pos<DIRECT_BLOCK){

    //direct
    sec_lev->level = 0;
    sec_lev->single_add = sec_pos;
    sec_lev->double_add = 0;
  }

  else if(sec_pos<(off_t)(DIRECT_BLOCK +INDIRECT_BLOCK)){

    //single indirect
    sec_lev->level = 1;
    sec_lev->single_add = sec_pos - (off_t)DIRECT_BLOCK;
    sec_lev->double_add = 0; 
  }
  else if(sec_pos<(off_t)DIRECT_BLOCK +INDIRECT_BLOCK * (INDIRECT_BLOCK+1)){

    //double indirect
     sec_lev->level = 2;
    sec_lev->single_add = (sec_pos - (off_t)DIRECT_BLOCK-(off_t)INDIRECT_BLOCK) / INDIRECT_BLOCK;
    sec_lev->double_add = (sec_pos - (off_t)DIRECT_BLOCK-(off_t)INDIRECT_BLOCK) % INDIRECT_BLOCK; 
  }
}

//offset을 byte로 변환
static inline off_t off_to_byte(int off){
  return (off_t)off*4;
}
// 새로 할당받은 물리주소의 block을 inode에 update
static bool update_inode(struct inode_disk * inode_disk, block_sector_t new_sector, struct sector_level sec_lev){

  struct indirect_block *indirect;
  struct indirect_block *double_indirect;
  block_sector_t sec_idx;
  switch(sec_lev.level){

    case 0:  
      //direct
      inode_disk->direct_map[sec_lev.single_add] = new_sector;
      break;
    case 1:
      //single indirect
      //새 block 할당
      if(sec_lev.single_add == 0){
        // table이 존재하지 않음
        if(free_map_allocate(1, &sec_idx)){
          inode_disk->indirect_map = sec_idx;
        }
      }

      indirect = calloc(1, BLOCK_SECTOR_SIZE);
      if(indirect == NULL){
        return false;
      }
      /*buffer cache에 쓰기*/
      indirect->map_arr[sec_lev.single_add] = new_sector;
      buffer_cache_write(inode_disk->indirect_map, (void*)indirect, off_to_byte(sec_lev.single_add), 4, off_to_byte(sec_lev.single_add));
      free(indirect);
      break;
    case 2:
      //double direct
       //새 block 할당
      if(sec_lev.single_add == 0 && sec_lev.double_add == 0){
        // table이 존재하지 않음
        if(free_map_allocate(1, &sec_idx)){
          inode_disk->double_indirect_map = sec_idx;
        }
      }

       //새 block 할당
      if(sec_lev.double_add == 0){
        // table이 존재하지 않음
        if(free_map_allocate(1, &sec_idx)){
          indirect = calloc(1, BLOCK_SECTOR_SIZE);
          if(indirect == NULL){
            return false;
          }
          indirect->map_arr[sec_lev.single_add] = sec_idx;
        }
        /*buffer cache에 쓰기*/
      
        buffer_cache_write(inode_disk->double_indirect_map, (void*)indirect, off_to_byte(sec_lev.single_add), 4, off_to_byte(sec_lev.single_add));
        free(indirect);
      }

      indirect = calloc(1, BLOCK_SECTOR_SIZE);
      if(indirect == NULL){
        return false;
      }

      double_indirect = calloc(1, BLOCK_SECTOR_SIZE);
      if(double_indirect == NULL){
        free(indirect);
        return false;
      }
      buffer_cache_read(inode_disk->double_indirect_map, (void*)indirect, 0, BLOCK_SECTOR_SIZE, 0);
      double_indirect->map_arr[sec_lev.double_add] = new_sector;
      buffer_cache_write(indirect->map_arr[sec_lev.single_add], (void*)double_indirect, off_to_byte(sec_lev.double_add), 4, off_to_byte(sec_lev.double_add));
      free(indirect);
      free(double_indirect);
      break;
    default:
      return false;
  }
  return true;
}

//파일의 크기가 커졌을 경우, 새로운 block할당
bool update_inode_length(struct inode_disk* inode_disk, off_t start, off_t end){

  // 크기의 변동이 없을 경우
  if(start == end){
    return true;
  }
  ASSERT(start<end);

  off_t size = end - start;
  off_t start_pos = start;
  void *temp = calloc(1, BLOCK_SECTOR_SIZE);
  int offset;
  

  //모든 block체크
  while(size > 0){

    offset = start_pos % BLOCK_SECTOR_SIZE;
    struct sector_level sec_lev;
    block_sector_t sec_idx;
    //이미 할당된 block이므로 다음block 부터 할당해야함
    //
    if(offset > 0){
      start_pos -= offset;
      size += offset;
    }
    else{
      //block을 새로 할당
      sec_idx = byte_to_sector(inode_disk, start_pos);

      if(free_map_allocate(1, &sec_idx)){

        find_lev(start_pos, &sec_lev);
        update_inode(inode_disk, sec_idx, sec_lev);
      }
      else{
        free(temp);
        return false;
      }
      buffer_cache_write(sec_idx, temp, 0, BLOCK_SECTOR_SIZE, 0);
    }
    //할당완료
    start_pos += BLOCK_SECTOR_SIZE;
    size -= BLOCK_SECTOR_SIZE;
  }
  free(temp);
  return true;
}

// block을 모두 free
static void free_inode(struct inode_disk *inode_disk){

  int index1, index2 = 0; // index1은 double indirext, index2는 single indirect의 sector
  struct indirect_block *indirect;
  struct indirect_block *double_indirect;
  
  //double indirect부터 제거
  if(inode_disk->double_indirect_map > 0){
      
      indirect = calloc(1, BLOCK_SECTOR_SIZE);
      if(indirect == NULL){
        return;
      }

      //첫번째 level을 찾아간다.
      buffer_cache_read(inode_disk->double_indirect_map, (void*)indirect, 0, BLOCK_SECTOR_SIZE,0);
      while(indirect->map_arr[index1]>0){
        double_indirect = calloc(1, BLOCK_SECTOR_SIZE);
        index2 = 0;
        if(double_indirect==NULL){
          free(indirect);
          return;
        }
        //두번째 level을 찾는다.
        buffer_cache_read(indirect->map_arr[index1], (void*)double_indirect, 0, BLOCK_SECTOR_SIZE,0);
        while(double_indirect->map_arr[index2]>0){
          //두번째 level할당 해제
          free_map_release(double_indirect->map_arr[index2],1);
          index2++;
        }
        free(double_indirect);
        //첫번째 level 해제
        free_map_release(indirect->map_arr[index1],1);
        index1++;
      }
      free(indirect);
      //0번째, 즉 inode에 연결되어 있는 연결 해제
      free_map_release(inode_disk->double_indirect_map, 1);
  }

  //single indirect 
  if(inode_disk->indirect_map > 0){
      
      index1 = 0;
      indirect = calloc(1, BLOCK_SECTOR_SIZE);
      if(indirect == NULL){
        return;
      }

      //첫번째 level을 찾아간다.
      buffer_cache_read(inode_disk->indirect_map, (void*)indirect, 0, BLOCK_SECTOR_SIZE,0);
      while(indirect->map_arr[index1]>0){
        
          free_map_release(indirect->map_arr[index1],1);
          index1++;
        }
        //첫번째 level 해제
      free(indirect);
      //0번째, 즉 inode에 연결되어 있는 연결 해제
      free_map_release(inode_disk->indirect_map, 1);
  }
  //direct 해제
  for(int i = 0; i<DIRECT_BLOCK; i++){
    //순서대로 저장되어 있으므로 0보다 작으면 바로 종료
    if(inode_disk->direct_map[i] < 0 ){
      return;
    }
    free_map_release(inode_disk->direct_map[i],1);
  }

}
/* List of open inodes, so that opening a single inode twice
   returns the same `struct inode'. */
static struct list open_inodes;

/* Initializes the inode module. */
void
inode_init (void) 
{
  list_init (&open_inodes);
}

/* Initializes an inode with LENGTH bytes of data and
   writes the new inode to sector SECTOR on the file system
   device.
   Returns true if successful.
   Returns false if memory or disk allocation fails. */
bool
inode_create (block_sector_t sector, off_t length)
{
  struct inode_disk *disk_inode = NULL;
  bool success = false;
  bool res;
  //printf("%d\n", INDIRECT_BLOCK);
  ASSERT (length >= 0);

  /* If this assertion fails, the inode structure is not exactly
     one sector in size, and you should fix that. */
  ASSERT (sizeof *disk_inode == BLOCK_SECTOR_SIZE);

  disk_inode = calloc (1, sizeof *disk_inode);
  if (disk_inode != NULL)
    {
      
      disk_inode->length = length;
      disk_inode->magic = INODE_MAGIC;
      if(length>0){
        //block의 크기가 0이 아니므로
        //새 block할당
        res = update_inode_length(disk_inode, 0, length);
        if(res == false){
          free(disk_inode);
          return false;
        }
      }
      //buffer cache로 쓰기
      buffer_cache_write(sector, disk_inode, 0, BLOCK_SECTOR_SIZE, 0);
      free(disk_inode);
      success = true;
    }
  return success;
}

/* Reads an inode from SECTOR
   and returns a `struct inode' that contains it.
   Returns a null pointer if memory allocation fails. */
struct inode *
inode_open (block_sector_t sector)
{
  struct list_elem *e;
  struct inode *inode;

  /* Check whether this inode is already open. */
  for (e = list_begin (&open_inodes); e != list_end (&open_inodes);
       e = list_next (e)) 
    {
      inode = list_entry (e, struct inode, elem);
      if (inode->sector == sector) 
        {
          inode_reopen (inode);
          return inode; 
        }
    }

  /* Allocate memory. */
  inode = malloc (sizeof *inode);
  if (inode == NULL)
    return NULL;

  /* Initialize. */
  lock_init(&inode->inode_lock);
  list_push_front (&open_inodes, &inode->elem);
  inode->sector = sector;
  inode->open_cnt = 1;
  inode->deny_write_cnt = 0;
  inode->removed = false;
  
  return inode;
}

/* Reopens and returns INODE. */
struct inode *
inode_reopen (struct inode *inode)
{
  if (inode != NULL)
    inode->open_cnt++;
  return inode;
}

/* Returns INODE's inode number. */
block_sector_t
inode_get_inumber (const struct inode *inode)
{
  return inode->sector;
}

//disk에서 inode읽기
static bool disk_inode_get(const struct inode *inode, struct inode_disk *inode_disk){
  
  return buffer_cache_read(inode->sector, (void*)inode_disk, 0, BLOCK_SECTOR_SIZE, 0);
}
/* Closes INODE and writes it to disk.
   If this was the last reference to INODE, frees its memory.
   If INODE was also a removed inode, frees its blocks. */
void
inode_close (struct inode *inode) 
{
  struct inode_disk inode_disk;
  /* Ignore null pointer. */
  if (inode == NULL)
    return;

  /* Release resources if this was the last opener. */
  if (--inode->open_cnt == 0)
    {
      /* Remove from inode list and release lock. */
      list_remove (&inode->elem);
 
      /* Deallocate blocks if removed. */
      if (inode->removed) 
        {
          buffer_cache_read(inode->sector, &inode_disk, 0, BLOCK_SECTOR_SIZE, 0);
          free_inode(&inode_disk);
          free_map_release(inode->sector,1);
        }

      free (inode); 
    }
}

/* Marks INODE to be deleted when it is closed by the last caller who
   has it open. */
void
inode_remove (struct inode *inode) 
{
  ASSERT (inode != NULL);
  inode->removed = true;
}




/* Reads SIZE bytes from INODE into BUFFER, starting at position OFFSET.
   Returns the number of bytes actually read, which may be less
   than SIZE if an error occurs or end of file is reached. */
off_t
inode_read_at (struct inode *inode, void *buffer_, off_t size, off_t offset) 
{
  struct inode_disk inode_disk;
  uint8_t *buffer = buffer_;
  off_t bytes_read = 0;

  disk_inode_get(inode, &inode_disk);

  while (size > 0) 
    {
      /* Disk sector to read, starting byte offset within sector. */
      block_sector_t sector_idx = byte_to_sector (&inode_disk, offset);
      int sector_ofs = offset % BLOCK_SECTOR_SIZE;

      /* Bytes left in inode, bytes left in sector, lesser of the two. */
      off_t inode_left = inode_length (inode) - offset;
      int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
      int min_left = inode_left < sector_left ? inode_left : sector_left;

      /* Number of bytes to actually copy out of this sector. */
      int chunk_size = size < min_left ? size : min_left;
      if (chunk_size <= 0)
        break;
      buffer_cache_read(sector_idx, buffer, bytes_read, chunk_size, sector_ofs);
      
      
      /* Advance. */
      size -= chunk_size;
      offset += chunk_size;
      bytes_read += chunk_size;
    }

  return bytes_read;
}

/* Writes SIZE bytes from BUFFER into INODE, starting at OFFSET.
   Returns the number of bytes actually written, which may be
   less than SIZE if end of file is reached or an error occurs.
   (Normally a write at end of file would extend the inode, but
   growth is not yet implemented.) */
off_t
inode_write_at (struct inode *inode, const void *buffer_, off_t size,
                off_t offset) 
{
  struct inode_disk inode_disk;
  const uint8_t *buffer = buffer_;
  off_t bytes_written = 0;

 

  if (inode->deny_write_cnt)
    return 0;
  

  disk_inode_get(inode, &inode_disk);
  lock_acquire(&inode->inode_lock);
  //길이가 기본 block길이보다 길 경우
  if((offset+size-1)>inode_disk.length-1){

    //update
    update_inode_length(&inode_disk, inode_disk.length, (offset+size-1));
    inode_disk.length = offset +size;
  }
  lock_release(&inode->inode_lock);

  while (size > 0) 
    {
      /* Sector to write, starting byte offset within sector. */
      block_sector_t sector_idx = byte_to_sector (&inode_disk, offset);
      int sector_ofs = offset % BLOCK_SECTOR_SIZE;

      /* Bytes left in inode, bytes left in sector, lesser of the two. */
      off_t inode_left = inode_disk.length - offset;
      int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
      int min_left = inode_left < sector_left ? inode_left : sector_left;

      /* Number of bytes to actually write into this sector. */
      int chunk_size = size < min_left ? size : min_left;
      if (chunk_size <= 0)
        break;
      
      buffer_cache_write(sector_idx, (void*)buffer, bytes_written, chunk_size, sector_ofs);

      /* Advance. */
      size -= chunk_size;
      offset += chunk_size;
      bytes_written += chunk_size;
    }
  
  buffer_cache_write(inode->sector, &inode_disk, 0, BLOCK_SECTOR_SIZE, 0);
  return bytes_written;
}

/* Disables writes to INODE.
   May be called at most once per inode opener. */
void
inode_deny_write (struct inode *inode) 
{
  inode->deny_write_cnt++;
  ASSERT (inode->deny_write_cnt <= inode->open_cnt);
}

/* Re-enables writes to INODE.
   Must be called once by each inode opener who has called
   inode_deny_write() on the inode, before closing the inode. */
void
inode_allow_write (struct inode *inode) 
{
  ASSERT (inode->deny_write_cnt > 0);
  ASSERT (inode->deny_write_cnt <= inode->open_cnt);
  inode->deny_write_cnt--;
}

/* Returns the length, in bytes, of INODE's data. */
off_t
inode_length (const struct inode *inode)
{
  struct inode_disk inode_disk;
  buffer_cache_read(inode->sector, &inode_disk, 0, BLOCK_SECTOR_SIZE, 0);
  return inode_disk.length;
}

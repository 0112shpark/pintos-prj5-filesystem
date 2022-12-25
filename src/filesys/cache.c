#include "filesys/cache.h"
#include "filesys/filesys.h"
#include <stdio.h>
#include <list.h>
#include "threads/malloc.h"
#include "threads/thread.h"
#include "free-map.h"

// cache를 위한 pointer
void * cache_ptr;

// buffer cache 초기화
void buffer_cache_init(){
    cache_ptr = malloc(BLOCK_SECTOR_SIZE * NUM_CACHE);
   
    for(int i = 0; i<NUM_CACHE; i++){
        buffer_cache_init_func(i);
        lock_init(&cache[i].buffer_cache_lock);
        
    }
}

// init helper funciton
void buffer_cache_init_func(int index){
    cache[index].valid_bit = true;
    cache[index].dirty_bit = false;
    cache[index].reference_bit = false;
    cache[index].buffer = cache_ptr + BLOCK_SECTOR_SIZE * index;
}

// buffer의 모든 데이터 disk로 쓰기- 마지막에 수행
void buffer_cache_terminate(void){
    buffer_cache_flush_all();
    free(cache_ptr);
}

// buffer cache에서 read, cache에 값이 없으면 disk에서 load
bool buffer_cache_read(block_sector_t sector_index, void *buffer, off_t read_bytes, int size, int sector_ofs){

    struct buffer_cache_entry *buffer_entry= buffer_cache_lookup(sector_index);
    
    //찾는 정보가 cache에 없으면 disk에서 읽어와야 함
    if(buffer_entry==-1){
        
        // 빈 자리가 있으면 그대로 return
        buffer_entry = buffer_cache_select_victim();
        buffer_entry->disk_sector = sector_index;
        buffer_entry->valid_bit = false;
        //disk에서부터 load
        //printf("D\n");
        block_read(fs_device, sector_index, buffer_entry->buffer);
     }

    //reference bit 설정
    //lock_acquire(&buffer_entry->buffer_cache_lock);
    buffer_entry->reference_bit = true;
    //lock_release(&buffer_entry->buffer_cache_lock);
    //cache에 copy
    memcpy(buffer + read_bytes, buffer_entry->buffer + sector_ofs, size);

    return true;
}

//buffer cache에 write, 자리가 없으면 제거
bool buffer_cache_write(block_sector_t sector_index, void *buffer, off_t written_bytes, int size, int sector_ofs){

    struct buffer_cache_entry *buffer_entry= buffer_cache_lookup(sector_index);

    //찾는 정보가 cache에 없으면 cache에 써야함
    if(buffer_entry==-1){
        //빈 공간 탐색
        buffer_entry = buffer_cache_select_victim();
        buffer_entry->disk_sector = sector_index;
        buffer_entry->valid_bit = false;
        // block에 write
        //printf("DDSS\n");
        block_read(fs_device, sector_index, buffer_entry->buffer);
        //printf("write done\n");
    }
    memcpy(buffer_entry->buffer + sector_ofs, buffer + written_bytes, size);
    lock_acquire(&buffer_entry->buffer_cache_lock);
    buffer_entry->dirty_bit = true;
    buffer_entry->reference_bit = true;
    lock_release(&buffer_entry->buffer_cache_lock);
    
    //cache에 write
    
    return true;
}

//주어진 sector index와 일치하는 데이터 return
struct buffer_cache_entry *buffer_cache_lookup(block_sector_t sector_index){

    for(int i = 0 ; i<NUM_CACHE; i++){
        if(!cache[i].valid_bit){
            if(cache[i].disk_sector == sector_index){
                return &cache[i];
            }
        }
    }
    return -1;
}

//second chance algorithm 사용
struct buffer_cache_entry *buffer_cache_select_victim(void){
    
    //빈 공간이 있으면 바로 return
    for(int i = 0; i<NUM_CACHE; i++){
        if(cache[i].valid_bit){
            return &cache[i];
        }
    }

    // second clock algorithm
    for (int i = 0; ; i = (i+1)%NUM_CACHE){
        
        //1이면 0 으로 변경
        if(cache[i].reference_bit){
            cache[i].reference_bit = 0;
        }
        else{
            //dirty bit이 설정되어 있으면 disk에 write
            if(cache[i].dirty_bit){
                buffer_cache_flush_entry(&cache[i]);
            }
            cache[i].disk_sector = -1;
            cache[i].reference_bit = false;
            cache[i].valid_bit = true;
            //cache[i].dirty_bit = false;
            return &cache[i];
        }
    }
    
}

//cache의 값을 disk에 쓰기
void buffer_cache_flush_entry(struct buffer_cache_entry *entry){
    
    block_write(fs_device, entry->disk_sector, entry->buffer);
    entry->dirty_bit = false;
}

// 모든 dirty bit설정된 buffer다 disk에 쓰기
void buffer_cache_flush_all(void){
    
    for(int i = 0; i<NUM_CACHE; i++){
        if(cache[i].dirty_bit){
            if(!cache[i].valid_bit){
                buffer_cache_flush_entry(&cache[i]);
            }
        }
    }
}




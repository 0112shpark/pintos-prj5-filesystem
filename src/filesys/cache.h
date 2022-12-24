#ifndef FILESYS_CACHE_H
#define FILESYS_CACHE_H

#include "devices/timer.h"
#include "threads/synch.h"
#include "devices/block.h"
#include "filesys/off_t.h"

#define NUM_CACHE 64

struct buffer_cache_entry{
    bool valid_bit;
    bool reference_bit;
    bool dirty_bit;
    block_sector_t disk_sector;
    
    void *buffer;
    struct lock buffer_cache_lock;
};

static struct buffer_cache_entry cache[NUM_CACHE];

void buffer_cache_init(void);
void buffer_cache_init_func(int index);
void buffer_cache_terminate(void);
bool buffer_cache_read(block_sector_t sector_index, void *buffer, off_t read_bytes, int size, int sector_ofs);
bool buffer_cache_write(block_sector_t sector_index, void *buffer, off_t written_bytes, int size, int sector_ofs);
struct buffer_cache_entry *buffer_cache_lookup(block_sector_t sector_index);
struct buffer_cache_entry *buffer_cache_select_victim(void);
void buffer_cache_flush_entry(struct buffer_cache_entry *entry);
void buffer_cache_flush_all(void);

#endif
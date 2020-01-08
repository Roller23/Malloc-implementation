#ifndef __ALLOCATOR_
#define __ALLOCATOR_

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <pthread.h>
#include <stdbool.h>

#define HEAP_INITIAL_PAGES 2
#define KB 1024
#define PAGE_SIZE (4 * KB)
#define SBRK_FAIL ((void *)-1)
#define HEADER_SIZE sizeof(chunk_t)
#define mem2block(mem) ((chunk_t *)((char *)(mem) - HEADER_SIZE))
#define block2mem(block) ((void *)((char *)(block) + HEADER_SIZE))
#define firstblock() ((chunk_t *)heap.data)
#define nextblock(block) ((chunk_t *)((char *)(block) + (block)->size + HEADER_SIZE))

#define MIN(A, B) ((A) < (B) ? (A) : (B))

typedef struct _chunk_t {
  size_t size;
  struct _chunk_t *next;
  struct _chunk_t *prev;
  bool free;
} chunk_t;

typedef struct {
  bool initialized;
  unsigned int pages;
  unsigned int blocks;
  chunk_t *last_block;
  uint8_t *data;
} heap_t;

// malloc API

void *_malloc(size_t size);
void *_calloc(size_t n, size_t size);
void *_realloc(void *memblock, size_t size);
void _free(void *memblock);

// internal functions

static void lock_heap(void);
static void unlock_heap(void);
static void *find_block(size_t size);
static chunk_t *split_chunk(chunk_t *chunk, size_t size);
static void coalesce_right(chunk_t *chunk);
static void use_chunk(chunk_t *chunk, size_t count);
static intptr_t get_page_multiple(intptr_t size);

#endif // __ALLOCATOR_
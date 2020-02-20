#ifndef __MALLOC_
#define __MALLOC_

#include <stdint.h>
#include <string.h>
#include <pthread.h>
#include <stdbool.h>
#include <unistd.h>

#define HEAP_INITIAL_PAGES 2
#define KB 1024
#define PAGE_SIZE (4 * KB)
#define SBRK_FAIL ((void *)-1)
#define HEADER_SIZE sizeof(chunk_t)
#define mem2chunk(mem) ((chunk_t *)((char *)(mem) - HEADER_SIZE))
#define chunk2mem(chunk) ((void *)((char *)(chunk) + HEADER_SIZE))
#define firstchunk() ((chunk_t *)heap.data)
#define nextchunk(chunk) ((chunk_t *)((char *)(chunk) + (chunk)->size + HEADER_SIZE))

#define MIN(A, B) ((A) < (B) ? (A) : (B))

typedef struct _chunk_t {
  size_t size;
  struct _chunk_t *next;
  struct _chunk_t *prev;
  bool free;
} chunk_t;

typedef struct {
  chunk_t *last_chunk;
  uint8_t *data;
  pthread_mutex_t mutex;
} heap_t;

// malloc API

#include "allocator.h"

// internal functions

static void lock_heap(void);
static void unlock_heap(void);
static void *find_chunk(size_t size);
static chunk_t *split_chunk(chunk_t *chunk, size_t size);
static void coalesce_right(chunk_t *chunk);
static void use_chunk(chunk_t *chunk, size_t count);
static intptr_t get_page_multiple(intptr_t size);

#endif // __MALLOC_
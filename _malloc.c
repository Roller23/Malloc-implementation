#include "_malloc.h"
#include <unistd.h>

static pthread_mutex_t heap_mutex;
static heap_t heap;

static void lock_heap(void) {
  pthread_mutex_lock(&heap_mutex);
}

static void unlock_heap(void) {
  pthread_mutex_unlock(&heap_mutex);
}

static void __attribute__((destructor)) heap_destroy(void) {
  if (!heap.initialized) {
    return;
  }
  pthread_mutex_destroy(&heap_mutex);
  heap.initialized = false;
}

static int __attribute__((constructor)) heap_setup(void) {
  if (heap.initialized) {
    return 0;
  }
  memset(&heap, 0, sizeof(heap));
  heap.pages = HEAP_INITIAL_PAGES;
  heap.data = sbrk(PAGE_SIZE * heap.pages);
  if (heap.data == SBRK_FAIL) {
    return -1;
  }
  chunk_t first_block;
  memset(&first_block, 0, sizeof(first_block));
  first_block.free = true;
  first_block.size = (PAGE_SIZE * heap.pages) - HEADER_SIZE;
  first_block.next = first_block.prev = NULL;
  memcpy(heap.data, &first_block, sizeof(first_block));
  heap.last_block = firstblock();
  pthread_mutex_init(&heap_mutex, NULL);
  heap.initialized = true;
  heap.blocks++;
  return 0;
}

static void *find_block(size_t size) {
  chunk_t *current = firstblock();
  while (current) {
    if (current->free && (current->size == size || current->size > (size + HEADER_SIZE))) {
      //it's either a perfect match or enough space for HEADER SIZE + size and some data
      return current;
    }
    current = current->next;
  }
  return NULL;
}

static chunk_t *split_chunk(chunk_t *chunk, size_t size) {
  bool change_last_block = chunk->next == NULL;
  size_t newsize = chunk->size - size - HEADER_SIZE;
  chunk_t newblock = {.size = newsize, .free = true};
  chunk_t *new_block_next = chunk->next;
  chunk->size = size;
  newblock.prev = chunk;
  newblock.next = chunk->next;
  chunk_t *new_block_ptr = nextblock(chunk);
  chunk->next = new_block_ptr;
  memcpy(new_block_ptr, &newblock, sizeof(chunk_t));
  if (new_block_next != NULL) {
    new_block_next->prev = new_block_ptr;
  }
  if (change_last_block) {
    heap.last_block = new_block_ptr;
  }
  heap.blocks++;
  return chunk;
}

static void coalesce_right(chunk_t *chunk) {
  chunk_t *right = chunk->next;
  bool change_last_block = right->next == NULL;
  chunk->size += right->size + HEADER_SIZE;
  chunk->next = right->next;
  if (chunk->next != NULL) {
    chunk->next->prev = chunk;
  }
  if (change_last_block) {
    heap.last_block = chunk;
  }
}

void _free(void *memblock) {
  lock_heap();
  if (memblock == NULL) {
    unlock_heap();
    return;
  }
  chunk_t *chunk = mem2block(memblock);
  chunk->free = true;
  chunk_t *left_block = chunk->prev;
  chunk_t *right_block = chunk->next;
  if (right_block != NULL && right_block->free) {
    coalesce_right(chunk);
    heap.blocks--;
  }
  if (left_block != NULL && left_block->free) {
    coalesce_right(left_block);
    heap.blocks--;
  }
  if (heap.last_block->free) {
    //release the memory to the OS
    size_t memory = heap.last_block->size + HEADER_SIZE;
    heap.last_block = heap.last_block->prev;
    if (heap.last_block != NULL) {
      heap.last_block->next = NULL;
    }
    heap.blocks--;
    sbrk(-memory);
  }
  unlock_heap();
}

static void use_block(chunk_t *chunk, size_t size) {
  if (chunk->size > (size + HEADER_SIZE)) {
    chunk = split_chunk(chunk, size);
  }
  chunk->free = false;
}

void *_malloc(size_t size) {
  if (size + HEADER_SIZE < size) {
    // unsigned overflow
    return NULL;
  }
  lock_heap();
  if (size == 0) {
    unlock_heap();
    return NULL;
  }
  chunk_t *free_block = find_block(size);
  if (free_block != NULL) {
    use_block(free_block, size);
    unlock_heap();
    return block2mem(free_block);
  }
  intptr_t mem = get_page_multiple(size + HEADER_SIZE);
  if (sbrk(mem) == SBRK_FAIL) {
    unlock_heap();
    return NULL;
  }
  int requested_pages = mem / PAGE_SIZE;
  heap.pages += requested_pages;
  if (heap.last_block->free) {
    heap.last_block->size += mem;
    chunk_t *selected_block = heap.last_block;
    use_block(selected_block, size);
    unlock_heap();
    return block2mem(selected_block);
  }
  chunk_t chunk = {.size = mem - HEADER_SIZE, .free = true};
  chunk_t *old_last_block = heap.last_block;
  chunk_t *new_last_block = nextblock(old_last_block);
  memcpy(new_last_block, &chunk, sizeof(chunk));
  heap.last_block = new_last_block;
  new_last_block->prev = old_last_block;
  new_last_block->next = NULL;
  old_last_block->next = new_last_block;
  heap.blocks++;
  use_block(new_last_block, size);
  unlock_heap();
  return block2mem(new_last_block);
}

void *_calloc(size_t n, size_t size) {
  if (size == 0) {
    return NULL;
  }
  // overflow test
  size_t totalsize = n * size;
  if (totalsize / n != size) {
    return NULL;
  }
  void *memory = _malloc(totalsize);
  if (memory == NULL) {
    return NULL;
  }
  lock_heap();
  memset(memory, 0, totalsize);
  unlock_heap();
  return memory;
}

void *_realloc(void *memblock, size_t size) {
  if (memblock == NULL) {
    return _malloc(size);
  }
  if (size == 0) {
    _free(memblock);
    return NULL;
  }
  chunk_t *block = mem2block(memblock);
  if (block->size == size) {
    return memblock;
  }
  void *new_usermem = _malloc(size);
  if (new_usermem == NULL) {
    return NULL;
  }
  chunk_t *new_block = mem2block(new_usermem);
  lock_heap();
  size_t to_copy = MIN(block->size, new_block->size);
  memcpy(new_usermem, memblock, to_copy);
  unlock_heap();
  _free(memblock);
  return new_usermem;
}

static intptr_t get_page_multiple(intptr_t size) {
  int remainder = size % PAGE_SIZE;
  if (remainder == 0) {
    return size;
  }
  return size + PAGE_SIZE - remainder;
}
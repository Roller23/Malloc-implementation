#include "_malloc.h"

static heap_t heap;

static inline void lock_heap(void) {
  pthread_mutex_lock(&heap.mutex);
}

static inline void unlock_heap(void) {
  pthread_mutex_unlock(&heap.mutex);
}

static void __attribute__((destructor)) heap_destroy(void) {
  pthread_mutex_destroy(&heap.mutex);
}

static void __attribute__((constructor)) heap_setup(void) {
  memset(&heap, 0, sizeof(heap));
  heap.data = sbrk(PAGE_SIZE * HEAP_INITIAL_PAGES);
  chunk_t *first_chunk = (chunk_t *)heap.data;
  first_chunk->free = true;
  first_chunk->size = (PAGE_SIZE * HEAP_INITIAL_PAGES) - HEADER_SIZE;
  first_chunk->next = first_chunk->prev = NULL;
  heap.last_chunk = firstchunk();
  pthread_mutex_init(&heap.mutex, NULL);
}

static void *find_chunk(size_t size) {
  chunk_t *current = firstchunk();
  while (current) {
    if (current->free && (current->size == size || current->size > (size + HEADER_SIZE))) {
      // it's either a perfect match or enough space for HEADER SIZE + size and some data
      return current;
    }
    current = current->next;
  }
  return NULL;
}

static chunk_t *split_chunk(chunk_t *chunk, size_t size) {
  bool change_last_chunk = (chunk->next == NULL);
  size_t newsize = chunk->size - size - HEADER_SIZE;
  chunk_t new_chunk = {.size = newsize, .free = true};
  chunk_t *new_chunk_next = chunk->next;
  chunk->size = size;
  new_chunk.prev = chunk;
  new_chunk.next = chunk->next;
  chunk_t *new_chunk_ptr = nextchunk(chunk);
  chunk->next = new_chunk_ptr;
  memcpy(new_chunk_ptr, &new_chunk, sizeof(chunk_t));
  if (new_chunk_next != NULL) {
    new_chunk_next->prev = new_chunk_ptr;
  }
  if (change_last_chunk) {
    heap.last_chunk = new_chunk_ptr;
  }
  return chunk;
}

static void coalesce_right(chunk_t *chunk) {
  chunk_t *right = chunk->next;
  bool change_last_chunk = right->next == NULL;
  chunk->size += right->size + HEADER_SIZE;
  chunk->next = right->next;
  if (chunk->next != NULL) {
    chunk->next->prev = chunk;
  }
  if (change_last_chunk) {
    heap.last_chunk = chunk;
  }
}

void _free(void *memblock) {
  lock_heap();
  if (memblock == NULL) {
    unlock_heap();
    return;
  }
  chunk_t *chunk = mem2chunk(memblock);
  chunk->free = true;
  chunk_t *left_chunk = chunk->prev;
  chunk_t *right_chunk = chunk->next;
  if (right_chunk != NULL && right_chunk->free) {
    coalesce_right(chunk);
  }
  if (left_chunk != NULL && left_chunk->free) {
    coalesce_right(left_chunk);
  }
  if (heap.last_chunk->free) {
    // release the memory to the OS
    size_t memory = heap.last_chunk->size + HEADER_SIZE;
    heap.last_chunk = heap.last_chunk->prev;
    if (heap.last_chunk != NULL) {
      heap.last_chunk->next = NULL;
    }
    sbrk(-memory);
  }
  unlock_heap();
}

static void use_chunk(chunk_t *chunk, size_t size) {
  if (chunk->size > (size + HEADER_SIZE)) {
    chunk = split_chunk(chunk, size);
  }
  chunk->free = false;
  chunk->size = size;
}

void *_malloc(uint32_t size) {
  if (size + HEADER_SIZE < size) {
    // unsigned integer overflow
    return NULL;
  }
  lock_heap();
  if (size == 0) {
    unlock_heap();
    return NULL;
  }
  chunk_t *free_chunk = find_chunk(size);
  if (free_chunk != NULL) {
    use_chunk(free_chunk, size);
    unlock_heap();
    return chunk2mem(free_chunk);
  }
  intptr_t mem = get_page_multiple(size + HEADER_SIZE);
  if (sbrk(mem) == SBRK_FAIL) {
    unlock_heap();
    return NULL;
  }
  if (heap.last_chunk->free) {
    heap.last_chunk->size += mem;
    chunk_t *selected_chunk = heap.last_chunk;
    use_chunk(selected_chunk, size);
    unlock_heap();
    return chunk2mem(selected_chunk);
  }
  chunk_t chunk = {.size = mem - HEADER_SIZE, .free = true};
  chunk_t *old_last_chunk = heap.last_chunk;
  chunk_t *new_last_chunk = nextchunk(old_last_chunk);
  memcpy(new_last_chunk, &chunk, sizeof(chunk));
  heap.last_chunk = new_last_chunk;
  new_last_chunk->prev = old_last_chunk;
  new_last_chunk->next = NULL;
  old_last_chunk->next = new_last_chunk;
  use_chunk(new_last_chunk, size);
  unlock_heap();
  return chunk2mem(new_last_chunk);
}

void *_calloc(uint32_t n, uint32_t size) {
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

void *_realloc(void *memblock, uint32_t size) {
  if (memblock == NULL) {
    return _malloc(size);
  }
  if (size == 0) {
    _free(memblock);
    return NULL;
  }
  chunk_t *chunk = mem2chunk(memblock);
  if (chunk->size == size) {
    return memblock;
  }
  void *new_usermem = _malloc(size);
  if (new_usermem == NULL) {
    return NULL;
  }
  chunk_t *new_chunk = mem2chunk(new_usermem);
  lock_heap();
  size_t to_copy = MIN(chunk->size, new_chunk->size);
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
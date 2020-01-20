#ifndef __ALLOCATOR_
#define __ALLOCATOR_

#include <stdint.h>

void *_malloc(uint32_t size);
void *_calloc(uint32_t n, uint32_t size);
void *_realloc(void *memblock, uint32_t size);
void _free(void *memblock);

#endif // __ALLOCATOR_
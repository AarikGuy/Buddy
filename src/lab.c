#include <stdio.h>
#include <stdbool.h>
#include <sys/mman.h>
#include <string.h>
#include <stddef.h>
#include <assert.h>
#include <signal.h>
#include <execinfo.h>
#include <unistd.h>
#include <time.h>
#ifdef __APPLE__
#include <sys/errno.h>
#else
#include <errno.h>
#endif

#include "lab.h"

#define handle_error_and_die(msg) \
    do                            \
    {                             \
        perror(msg);              \
        raise(SIGKILL);          \
    } while (0)

/**
 * @brief Convert bytes to the correct K value
 *
 * @param bytes the number of bytes
 * @return size_t the K value that will fit bytes
 */
size_t btok(size_t bytes)
{
    size_t k = 0;
    size_t size = 1;
    
    //Finds the smallest k where 2^k >= bytes
    while (size < bytes) {
        k++;
        // Doubles the size equivalent to 2^k
        size <<= 1;
        
        // Handles any potential overflow
        if (size < (1UL << k)) {  // This checks if overflow occurred
            return MAX_K - 1;
        }
    }
    
    return k;
}

struct avail *buddy_calc(struct buddy_pool *pool, struct avail *buddy)
{
     // Calculates the offset from the base address
     uintptr_t base_addr = (uintptr_t)pool->base;
     uintptr_t buddy_addr = (uintptr_t)buddy;
     uintptr_t offset = buddy_addr - base_addr;
     
     // The buddy of a block with offset X and size 2^k is at offset X XOR 2^k
     size_t block_size = (UINT64_C(1) << buddy->kval);
     uintptr_t buddy_offset = offset ^ block_size;
     
     // Calculates the address
     struct avail *buddy_block = (struct avail *)(base_addr + buddy_offset);
     
     return buddy_block;
}

void *buddy_malloc(struct buddy_pool *pool, size_t size)
{
    // Validates the parameters
    if (size == 0 || pool == NULL) {
        errno = EINVAL;
        return NULL;
    }

    // Check if the requested size exceeds the available memory
    if (size > pool->numbytes) { 
        errno = ENOMEM;  
        return NULL;
    } 
    
    // Gets the kval for the requested size with enough room for the tag and kval fields
    size_t req_size = size + sizeof(struct avail);
    size_t kval = btok(req_size);
    
    // This makes sure the block is at least the minimum size
    if (kval < SMALLEST_K) {
        kval = SMALLEST_K;
    }
    
    // Find an available block
    size_t curr_kval = kval;
    struct avail *block = NULL;

    while (curr_kval <= pool->kval_m) {
        if (pool->avail[curr_kval].next != &pool->avail[curr_kval]) {
            block = pool->avail[curr_kval].next;
            break;
        }
        curr_kval++;
    }
    
    // If no block found, memory exhaustion due to fragmentation, set errno to ENOMEM
    if (block == NULL) {
        errno = ENOMEM;
        return NULL;
    }

    // Remove block from free list
    block->next->prev = block->prev;
    block->prev->next = block->next;
    
    // Split blocks if necessary
    while (curr_kval > kval) {
        curr_kval--;
        
        size_t buddy_size = (UINT64_C(1) << curr_kval);
        struct avail *buddy = (struct avail *)((char *)block + buddy_size);
        
        buddy->tag = BLOCK_AVAIL;
        buddy->kval = curr_kval;
        
        buddy->next = pool->avail[curr_kval].next;
        buddy->prev = &pool->avail[curr_kval];
        pool->avail[curr_kval].next->prev = buddy;
        pool->avail[curr_kval].next = buddy;
    }

    block->tag = BLOCK_RESERVED;
    block->kval = kval;

    // Return a pointer to the user memory
    return (void *)((char *)block + sizeof(struct avail));
}


void buddy_free(struct buddy_pool *pool, void *ptr)
{

    // Validates the parameters
    if (ptr == NULL || pool == NULL) {
        return;
    }

     // Checks if the pointer is within the managed memory range
    if ((char*)ptr < (char*)pool->base || (char*)ptr >= (char*)pool->base + pool->numbytes) {
        return; // Pointer is outside our memory pool
    }
        
    // Gets the block header
    struct avail *block = (struct avail *)((char *)ptr - sizeof(struct avail));
        
    // Validates the block
    if (block->tag != BLOCK_RESERVED) {
        return; // Not a valid block or already freed
    }
        
    // Marks the block as available
    block->tag = BLOCK_AVAIL;
        
    // Tries to coalesce with buddies
    while (block->kval < pool->kval_m) {
        // Finds the buddy
        struct avail *buddy = buddy_calc(pool, block);
            
        // If buddy is not free or has a different size we can't merge
        if (buddy->tag != BLOCK_AVAIL || buddy->kval != block->kval) {
            break;
        }
            
        // Remove the buddy from its free list
        buddy->next->prev = buddy->prev;
        buddy->prev->next = buddy->next;
            
        // Determines which block is the lower one in memory
        if (buddy < block) {
            block = buddy;
        }
            
        block->kval++;
    }
        
    // Add the block to the correct free list
    block->next = pool->avail[block->kval].next;
    block->prev = &pool->avail[block->kval];
    pool->avail[block->kval].next->prev = block;
    pool->avail[block->kval].next = block;
}

/**
 * @brief This is a simple version of realloc.
 *
 * @param poolThe memory pool
 * @param ptr  The user memory
 * @param size the new size requested
 * @return void* pointer to the new user memory
 */ // I just commented this out to get rid of the warnings
// void *buddy_realloc(struct buddy_pool *pool, void *ptr, size_t size)
// {
//     //Required for Grad Students
//     //Optional for Undergrad Students
// }

void buddy_init(struct buddy_pool *pool, size_t size)
{
    size_t kval = 0;
    if (size == 0)
        kval = DEFAULT_K;
    else
        kval = btok(size);

    if (kval < MIN_K)
        kval = MIN_K;
    if (kval > MAX_K)
        kval = MAX_K - 1;

    //make sure pool struct is cleared out
    memset(pool,0,sizeof(struct buddy_pool));
    pool->kval_m = kval;
    pool->numbytes = (UINT64_C(1) << pool->kval_m);
    //Memory map a block of raw memory to manage
    pool->base = mmap(
        NULL,                               /*addr to map to*/
        pool->numbytes,                     /*length*/
        PROT_READ | PROT_WRITE,             /*prot*/
        MAP_PRIVATE | MAP_ANONYMOUS,        /*flags*/
        -1,                                 /*fd -1 when using MAP_ANONYMOUS*/
        0                                   /* offset 0 when using MAP_ANONYMOUS*/
    );
    if (MAP_FAILED == pool->base)
    {
        handle_error_and_die("buddy_init avail array mmap failed");
    }

    //Set all blocks to empty. We are using circular lists so the first elements just point
    //to an available block. Thus the tag, and kval feild are unused burning a small bit of
    //memory but making the code more readable. We mark these blocks as UNUSED to aid in debugging.
    for (size_t i = 0; i <= kval; i++)
    {
        pool->avail[i].next = pool->avail[i].prev = &pool->avail[i];
        pool->avail[i].kval = i;
        pool->avail[i].tag = BLOCK_UNUSED;
    }

    //Add in the first block
    pool->avail[kval].next = pool->avail[kval].prev = (struct avail *)pool->base;
    struct avail *m = pool->avail[kval].next;
    m->tag = BLOCK_AVAIL;
    m->kval = kval;
    m->next = m->prev = &pool->avail[kval];
}

void buddy_destroy(struct buddy_pool *pool)
{
    int rval = munmap(pool->base, pool->numbytes);
    if (-1 == rval)
    {
        handle_error_and_die("buddy_destroy avail array");
    }
    //Zero out the array so it can be reused it needed
    memset(pool,0,sizeof(struct buddy_pool));
}

#define UNUSED(x) (void)x

/**
 * This function can be useful to visualize the bits in a block. This can
 * help when figuring out the buddy_calc function!
 */
static void printb(unsigned long int b)
{
     size_t bits = sizeof(b) * 8;
     unsigned long int curr = UINT64_C(1) << (bits - 1);
     for (size_t i = 0; i < bits; i++)
     {
          if (b & curr)
          {
               printf("1");
          }
          else
          {
               printf("0");
          }
          curr >>= 1L;
     }
}

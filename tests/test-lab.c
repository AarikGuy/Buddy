#include <assert.h>
#include <stdlib.h>
#include <time.h>
#ifdef __APPLE__
#include <sys/errno.h>
#else
#include <errno.h>
#endif
#include "harness/unity.h"
#include "../src/lab.h"


void setUp(void) {
  // set stuff up here
}

void tearDown(void) {
  // clean stuff up here
}

/**
 * Check the pool to ensure it is full.
 */
void check_buddy_pool_full(struct buddy_pool *pool)
{
  //A full pool should have all values 0-(kval-1) as empty
  for (size_t i = 0; i < pool->kval_m; i++)
    {
      assert(pool->avail[i].next == &pool->avail[i]);
      assert(pool->avail[i].prev == &pool->avail[i]);
      assert(pool->avail[i].tag == BLOCK_UNUSED);
      assert(pool->avail[i].kval == i);
    }

  //The avail array at kval should have the base block
  assert(pool->avail[pool->kval_m].next->tag == BLOCK_AVAIL);
  assert(pool->avail[pool->kval_m].next->next == &pool->avail[pool->kval_m]);
  assert(pool->avail[pool->kval_m].prev->prev == &pool->avail[pool->kval_m]);

  //Check to make sure the base address points to the starting pool
  //If this fails either buddy_init is wrong or we have corrupted the
  //buddy_pool struct.
  assert(pool->avail[pool->kval_m].next == pool->base);
}

/**
 * Check the pool to ensure it is empty.
 */
void check_buddy_pool_empty(struct buddy_pool *pool)
{
  //An empty pool should have all values 0-(kval) as empty
  for (size_t i = 0; i <= pool->kval_m; i++)
    {
      assert(pool->avail[i].next == &pool->avail[i]);
      assert(pool->avail[i].prev == &pool->avail[i]);
      assert(pool->avail[i].tag == BLOCK_UNUSED);
      assert(pool->avail[i].kval == i);
    }
}


void test_allocation(void) {
  struct buddy_pool pool;
  buddy_init(&pool, 1024);  

  void *ptr1 = buddy_malloc(&pool, 64);
  assert(ptr1 != NULL);
  
  void *ptr2 = buddy_malloc(&pool, 128);
  assert(ptr2 != NULL);
  
  buddy_free(&pool, ptr1);
  buddy_free(&pool, ptr2);
  buddy_destroy(&pool);
}

void test_coalescing(void) {
  struct buddy_pool pool;
  buddy_init(&pool, 1024);

  void *ptr1 = buddy_malloc(&pool, 64);
  void *ptr2 = buddy_malloc(&pool, 64);
  
  assert(ptr1 != NULL && ptr2 != NULL);
  
  buddy_free(&pool, ptr1);
  buddy_free(&pool, ptr2);
  
  // The buddy blocks should merge
  struct avail *block = (struct avail *)((char *)ptr1 - sizeof(struct avail));
  assert(block->tag == BLOCK_AVAIL);
  assert(block->kval > btok(64)); // Ensure coalescing occurred
  
  buddy_destroy(&pool);
}

/**
 * Test multiple allocations of different sizes to ensure splitting and coalescing work correctly
 */
void test_buddy_multiple_allocations(void) {
  fprintf(stderr, "->Testing multiple allocations and frees\n");
  struct buddy_pool pool;
  size_t kval = 10; // 1024 bytes
  size_t size = UINT64_C(1) << kval;
  buddy_init(&pool, size);

  // Allocate several blocks of different sizes
  void *mem1 = buddy_malloc(&pool, 32);
  void *mem2 = buddy_malloc(&pool, 64);
  void *mem3 = buddy_malloc(&pool, 128);
  void *mem4 = buddy_malloc(&pool, 16);
  
  // Verify all allocations succeeded
  assert(mem1 != NULL);
  assert(mem2 != NULL);
  assert(mem3 != NULL);
  assert(mem4 != NULL);
  
  // Free in a different order than allocated
  buddy_free(&pool, mem3);
  buddy_free(&pool, mem1);
  buddy_free(&pool, mem4);
  buddy_free(&pool, mem2);
  
  // After all frees, the pool should be back to original state
  check_buddy_pool_full(&pool);
  buddy_destroy(&pool);
}

/**
 * Test buddy_calc function by allocating two blocks that should be buddies
 * and then freeing them to ensure they coalesce correctly
 */
void test_buddy_calc(void) {
  fprintf(stderr, "->Testing buddy calculation and coalescing\n");
  struct buddy_pool pool;
  size_t kval = 8; // 256 bytes
  size_t size = UINT64_C(1) << kval;
  buddy_init(&pool, size);
  
  // Allocate a block large enough to be split exactly once
  size_t block_size = (size / 2) - sizeof(struct avail);
  void *mem1 = buddy_malloc(&pool, block_size);
  assert(mem1 != NULL);
  
  // The next allocation should get the buddy of the first block
  void *mem2 = buddy_malloc(&pool, block_size);
  assert(mem2 != NULL);
  
  // Get the block headers
  struct avail *block1 = (struct avail *)((char *)mem1 - sizeof(struct avail));
  struct avail *block2 = (struct avail *)((char *)mem2 - sizeof(struct avail));
  
  // Verify they have the same kval (should be kval-1)
  assert(block1->kval == block2->kval);
  assert(block1->kval == kval - 1);
  
  // Calculate what should be the buddy of block1
  struct avail *calc_buddy = buddy_calc(&pool, block1);
  
  // Verify buddy_calc works correctly
  assert(calc_buddy == block2);
  
  // Free both blocks - they should coalesce
  buddy_free(&pool, mem1);
  buddy_free(&pool, mem2);
  
  // Pool should be back to original state
  check_buddy_pool_full(&pool);
  buddy_destroy(&pool);
}

/**
 * Test edge cases like allocating size 0 and NULL pointers
 */
void test_buddy_edge_cases(void) {
  fprintf(stderr, "->Testing edge cases\n");
  struct buddy_pool pool;
  size_t kval = MIN_K;
  size_t size = UINT64_C(1) << kval;
  buddy_init(&pool, size);
  
  // Test allocating 0 bytes 
  void *mem1 = buddy_malloc(&pool, 0);
  assert(mem1 == NULL);
  
  // Test freeing NULL 
  buddy_free(&pool, NULL);
  
  // Pool should still be full
  check_buddy_pool_full(&pool);
  
  // Test freeing an invalid pointer 
  char dummy[10];
  buddy_free(&pool, dummy);
  
  // Pool should still be full
  check_buddy_pool_full(&pool);
  
  buddy_destroy(&pool);
}

/**
 * Test the btok function to ensure it calculates correct k values
 */
void test_btok(void) {
  fprintf(stderr, "->Testing btok function\n");
  
  // Test exact powers of 2
  assert(btok(1) == 0);
  assert(btok(2) == 1);
  assert(btok(4) == 2);
  assert(btok(8) == 3);
  assert(btok(16) == 4);
  assert(btok(32) == 5);
  
  // Test values that are not powers of 2
  assert(btok(3) == 2);  // Needs 2^2=4 bytes
  assert(btok(5) == 3);  // Needs 2^3=8 bytes
  assert(btok(15) == 4); // Needs 2^4=16 bytes
  assert(btok(17) == 5); // Needs 2^5=32 bytes
  
  // Test larger values
  assert(btok(1023) == 10); // Needs 2^10=1024 bytes
  assert(btok(1024) == 10);
  assert(btok(1025) == 11); // Needs 2^11=2048 bytes
}

/**
 * Test case for buddy_malloc with a size that requires SMALLEST_K adjustment
 */
void test_buddy_smallest_block(void) {
  fprintf(stderr, "->Testing smallest block allocation\n");
  struct buddy_pool pool;
  size_t kval = 8; // 256 bytes
  size_t size = UINT64_C(1) << kval;
  buddy_init(&pool, size);
  
  // Allocate a very small block that should be adjusted to SMALLEST_K
  size_t tiny_size = 1; // This should be smaller than what would require SMALLEST_K
  void *mem = buddy_malloc(&pool, tiny_size);
  assert(mem != NULL);
  
  // Get the block header and verify it's at least SMALLEST_K
  struct avail *block = (struct avail *)((char *)mem - sizeof(struct avail));
  assert(block->kval >= SMALLEST_K);
  
  buddy_free(&pool, mem);
  check_buddy_pool_full(&pool);
  buddy_destroy(&pool);
}

/**
 * Test allocations of various sizes to ensure the splitting algorithm works correctly
 */
void test_buddy_split_algorithm(void) {
  fprintf(stderr, "->Testing block splitting algorithm\n");
  struct buddy_pool pool;
  size_t kval = 10; // 1024 bytes
  size_t size = UINT64_C(1) << kval;
  buddy_init(&pool, size);
  
  // Allocate a block that will require splitting
  void *mem1 = buddy_malloc(&pool, 100);
  assert(mem1 != NULL);
  
  // The block should be split to the appropriate size
  struct avail *block1 = (struct avail *)((char *)mem1 - sizeof(struct avail));
  size_t expected_kval = btok(100 + sizeof(struct avail));
  if (expected_kval < SMALLEST_K) expected_kval = SMALLEST_K;
  assert(block1->kval == expected_kval);
  
  // Allocate another block of a different size
  void *mem2 = buddy_malloc(&pool, 200);
  assert(mem2 != NULL);
  
  struct avail *block2 = (struct avail *)((char *)mem2 - sizeof(struct avail));
  expected_kval = btok(200 + sizeof(struct avail));
  if (expected_kval < SMALLEST_K) expected_kval = SMALLEST_K;
  assert(block2->kval == expected_kval);
  
  buddy_free(&pool, mem1);
  buddy_free(&pool, mem2);
  check_buddy_pool_full(&pool);
  buddy_destroy(&pool);
}

/**
 * Test freeing an already freed block (double free)
 */
void test_buddy_double_free(void) {
  fprintf(stderr, "->Testing double free safety\n");
  struct buddy_pool pool;
  size_t kval = 8;
  size_t size = UINT64_C(1) << kval;
  buddy_init(&pool, size);
  
  // Allocate a block
  void *mem = buddy_malloc(&pool, 64);
  assert(mem != NULL);
  
  // Free it once
  buddy_free(&pool, mem);
  
  // Free it again 
  buddy_free(&pool, mem);
  
  // Pool should still be in a valid state
  check_buddy_pool_full(&pool);
  buddy_destroy(&pool);
}

/**
 * Test allocating 1 byte to make sure we split the blocks all the way down
 * to MIN_K size. Then free the block and ensure we end up with a full
 * memory pool again
 */
void test_buddy_malloc_one_byte(void)
{
  fprintf(stderr, "->Test allocating and freeing 1 byte\n");
  struct buddy_pool pool;
  int kval = MIN_K;
  size_t size = UINT64_C(1) << kval;
  buddy_init(&pool, size);
  void *mem = buddy_malloc(&pool, 1);
  //Make sure correct kval was allocated
  buddy_free(&pool, mem);
  check_buddy_pool_full(&pool);
  buddy_destroy(&pool);
}

/**
 * Tests the allocation of one massive block that should consume the entire memory
 * pool and makes sure that after the pool is empty we correctly fail subsequent calls.
 */
void test_buddy_malloc_one_large(void)
{
  fprintf(stderr, "->Testing size that will consume entire memory pool\n");
  struct buddy_pool pool;
  size_t bytes = UINT64_C(1) << MIN_K;
  buddy_init(&pool, bytes);

  //Ask for an exact K value to be allocated. This test makes assumptions on
  //the internal details of buddy_init.
  size_t ask = bytes - sizeof(struct avail);
  void *mem = buddy_malloc(&pool, ask);
  assert(mem != NULL);

  //Move the pointer back and make sure we got what we expected
  struct avail *tmp = (struct avail *)mem - 1;
  assert(tmp->kval == MIN_K);
  assert(tmp->tag == BLOCK_RESERVED);
  check_buddy_pool_empty(&pool);

  //Verify that a call on an empty tool fails as expected and errno is set to ENOMEM.
  void *fail = buddy_malloc(&pool, 5);
  assert(fail == NULL);
  assert(errno = ENOMEM);

  //Free the memory and then check to make sure everything is OK
  buddy_free(&pool, mem);
  check_buddy_pool_full(&pool);
  buddy_destroy(&pool);
}

/**
 * Tests to make sure that the struct buddy_pool is correct and all fields
 * have been properly set kval_m, avail[kval_m], and base pointer after a
 * call to init
 */
void test_buddy_init(void)
{
  fprintf(stderr, "->Testing buddy init\n");
  //Loop through all kval MIN_k-DEFAULT_K and make sure we get the correct amount allocated.
  //We will check all the pointer offsets to ensure the pool is all configured correctly
  for (size_t i = MIN_K; i <= DEFAULT_K; i++)
    {
      size_t size = UINT64_C(1) << i;
      struct buddy_pool pool;
      buddy_init(&pool, size);
      check_buddy_pool_full(&pool);
      buddy_destroy(&pool);
    }
}


int main(void) {
  time_t t;
  unsigned seed = (unsigned)time(&t);
  fprintf(stderr, "Random seed:%d\n", seed);
  srand(seed);
  printf("Running memory tests.\n");

  UNITY_BEGIN();
  RUN_TEST(test_buddy_init);
  RUN_TEST(test_buddy_malloc_one_byte);
  RUN_TEST(test_buddy_malloc_one_large);
  RUN_TEST(test_allocation);
  RUN_TEST(test_coalescing);
  RUN_TEST(test_btok);
  RUN_TEST(test_buddy_malloc_one_byte);
  RUN_TEST(test_buddy_malloc_one_large);
  RUN_TEST(test_buddy_multiple_allocations);
  RUN_TEST(test_buddy_calc);
  RUN_TEST(test_buddy_edge_cases);
  RUN_TEST(test_buddy_smallest_block);
  RUN_TEST(test_buddy_double_free);
  RUN_TEST(test_buddy_split_algorithm);
return UNITY_END();
}

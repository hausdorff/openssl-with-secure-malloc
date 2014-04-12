/*
 * Memory allocator for secure heap for OpenSSL key storage.
 * Copyright, 2001-2014, Akamai Technologies. All Rights Reserved.
 * Distributed under the terms of the OpenSSL license.
 *
 * Note that to improve performance and simplfy the code, this allocator
 * works only in the same thread where we called the init function;
 * trying to allocate/free blocks from different threads will
 * just delegate the calls to the standard malloc library. 
 */

#include <pthread.h>
#include <string.h>
#include <sys/mman.h>
#include <stdlib.h>  
#include <assert.h>

#include "secure_malloc.h"

extern void OPENSSL_cleanse(void *ptr, size_t len);

/*
 * Set to 1 when secure_malloc_init() is called successfully.  Can
 * never be set back to 0
 */
int secure_allocation_support = 0;

static pthread_mutex_t secure_allocation_lock = PTHREAD_MUTEX_INITIALIZER;

#define LOCK() pthread_mutex_lock(&secure_allocation_lock)
#define UNLOCK() pthread_mutex_unlock(&secure_allocation_lock)

static pthread_key_t secure_allocation_key;
static const int secure_yes = 1;
static const int secure_no = 0;

static char *arena = NULL;
static size_t arena_size = 0;

/* The low-level secure heap interface. */
extern void *cmm_init(int size, int mem_min_unit, int overrun_bytes);
extern void *cmm_malloc(int size);
extern int cmm_free(void *lamb);
extern void *cmm_realloc(void *lamb, int size);

static int secure_allocation_enabled()
{
  if (!secure_allocation_support)
  {
    return 0;
  }
  int* answer = (int*)pthread_getspecific(secure_allocation_key);
  return answer == &secure_yes;
}

static void secure_allocation_enable(int status)
{
  if (secure_allocation_support)
  {
    pthread_setspecific(secure_allocation_key,
            status ? &secure_yes : &secure_no);
  }
}

/*
 * Start/stop secure allocation.
 */
int start_secure_allocation()
{
  int ret = secure_allocation_enabled();
  if (ret == 0)
  {
    secure_allocation_enable(1);
  }

  return ret;
}

int stop_secure_allocation() 
{
  int ret = secure_allocation_enabled();
  if (ret == 1)
  {
    secure_allocation_enable(0);
  }
  
  return ret;
}

void flush_secure_arena()
{
  if (arena)
    memset(arena, 0, arena_size);
}

/* Module initialization, returns >0 upon success */
int secure_malloc_init(size_t size, int mem_min_unit, int overrun_bytes)
{
  int ret = 0;
  arena_size = size;

  LOCK();
  if (arena)
  {
    assert(0);
  }

  else if ((arena = (char *) cmm_init(arena_size, mem_min_unit, overrun_bytes)) == NULL)
  {
  }
  else if (mlock(arena, arena_size))
  {
  }
  else if (pthread_key_create(&secure_allocation_key, 0) != 0)
  {
  }
  else
  {
    secure_allocation_support = 1;
    ret = 1;
  }

  /* MADV_DONTDUMP is supported from Kernel 3.4 and from glibc 2.16 */
#ifdef MADV_DONTDUMP
  if (madvise(arena, arena_size, MADV_DONTDUMP) == 0)
  {
    ret = 2;
  }
#endif

  UNLOCK();
  return ret;
}

/* Helper func to figure out whether a pointer was allocated from the
   secure chunk. 
*/
static int is_secured_ptr(void *ptr)
{
  return secure_allocation_support
      && (char*)ptr >= arena && (char*)ptr < arena + arena_size;
}

void *secure_calloc(size_t nmemb, size_t size)
{
  void *ret;
  int tot_size = nmemb*size;

  if (!secure_allocation_enabled())
    return calloc(nmemb,size);
  LOCK();
  ret = cmm_malloc(tot_size);
  if (ret) 
  {
    memset(ret,0,tot_size);
  }
  UNLOCK();
  return ret;
}

void *secure_malloc(size_t size)
{
  void *ret;

  if (!secure_allocation_enabled())
    return malloc(size);
  LOCK();
  ret = cmm_malloc(size);
  UNLOCK();
  return ret;
}

void *secure_strdup(const char *str)
{
  return strcpy(secure_malloc(strlen(str) + 1), str);
}

void secure_free(void *ptr)
{
  if (secure_allocation_support && is_secured_ptr(ptr))
  {
    LOCK();
    cmm_free(ptr);
    UNLOCK();
  }
  else
  {
    free(ptr);
  }

}

void *secure_realloc(void *ptr, size_t size)
{
  void *ret;

  if (secure_allocation_support && is_secured_ptr(ptr))
  {
    LOCK();
    ret = cmm_realloc(ptr,size);
    UNLOCK();
  }
  else 
  {
    ret = realloc(ptr,size);
  }
  
  return ret;
}

void *secure_realloc_clean(void *ptr, int old_len, size_t size)
{
  void *ret;

  ret = secure_malloc(size);
  if (ret)
    memcpy(ret, ptr, old_len);

  OPENSSL_cleanse(ptr, old_len);
  secure_free(ptr);

  return ret;
}

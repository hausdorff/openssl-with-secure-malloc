/*
 * Memory allocator for secure heap for OpenSSL key storage.
 * Copyright, 2001-2014, Akamai Technologies. All Rights Reserved.
 * Distributed under the terms of the OpenSSL license.
 */

#ifndef __openssl_secure_malloc_h
#define __openssl_secure_malloc_h

#ifdef __cplusplus
extern "C" {
#endif

/* Global flag to designate whether secure malloc support is turned on */ 
extern int secure_allocation_support;

/* Secure versions of the malloc interface functions */
extern void *secure_calloc(size_t nmemb, size_t size);
extern void *secure_malloc(size_t size);
extern void *secure_strdup(const char *str);
extern void secure_free(void *ptr);
extern void *secure_realloc(void *ptr, size_t size);
extern void *secure_realloc_clean(void *ptr, int old_len, size_t size);

/* Module initialization including setting secure_malloc_support. */
extern int secure_malloc_init(size_t arena_size, int mem_min_unit, int overrun_bytes);

/*
 * Enabling/Disabling the secure allocation.  Use like this to ensure
 * proper nesting:
 *   int x = start_secure_allocation();
 *   .... do some work, calling OPENSSL_malloc etc ...
 *   if (x) stop_secure_allocation();
 */
extern int start_secure_allocation();
extern int stop_secure_allocation();

/* Erasing the content of all allocated buffers */
extern void flush_secure_arena();

#ifdef __cplusplus
}
#endif

#endif

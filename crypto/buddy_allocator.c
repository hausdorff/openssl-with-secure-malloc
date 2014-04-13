/*
 * Memory allocator for secure heap for OpenSSL key storage.
 * Copyright, 2001-2014, Akamai Technologies. All Rights Reserved.
 * Distributed under the terms of the OpenSSL license.
 */
#include <stdlib.h>  
#include <assert.h> 
#include <unistd.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/param.h>

static void *cmm_arena = NULL;
static void **cmm_free_list = NULL;
static int cmm_max_free_lists;
static int mem_arena_size = 0;
static int Mem_min_unit  = 0;
static int Overrun_bytes = 0;

typedef unsigned char u_int8;

static u_int8 *cmm_bittable;
static u_int8 *cmm_bitmalloc;
/* size in bits */
static int cmm_bittable_size;

#define SETBIT(_a,_b) ((_a)[(_b)>>3] |= (1<<((_b)&7)))
#define CLEARBIT(_a,_b) ((_a)[(_b)>>3] &= (0xff&~(1<<((_b)&7))))
#define TESTBIT(_a,_b) ((_a)[(_b)>>3] & (1<<((_b)&7)))

static void cmm_add_to_list(void **list, void *lamb);
static void cmm_remove_from_list(void *lamb, void *list);
static void *mybuddy(void *lamb, int list);
static int getlist(void *lamb);
static int testbit(void *lamb, int list, u_int8 *table);
static void clearbit(void *lamb, int list, u_int8 *table);
static void set_bit(void *lamb, int list, u_int8 *table);

void *
cmm_init(int size, int mem_min_unit, int overrun_bytes)
{
    int i;
    size_t pgsize = (size_t)sysconf(_SC_PAGE_SIZE);
    size_t aligned = (pgsize + size + (pgsize - 1)) & ~(pgsize - 1);

    mem_arena_size = size;
    Mem_min_unit   = mem_min_unit,
    Overrun_bytes  = overrun_bytes;
    /* make sure mem_arena_size and Mem_min_unit are powers of 2 */
    assert(mem_arena_size > 0);
    assert(mem_min_unit > 0);
    assert(0 == ((mem_arena_size-1)&mem_arena_size));
    assert(0 == ((Mem_min_unit-1)&Mem_min_unit));

    cmm_bittable_size = (mem_arena_size/Mem_min_unit) * 2;

    i = cmm_bittable_size;
    cmm_max_free_lists = -1;
    while(i) {
	i>>=1;
	cmm_max_free_lists++;
    }

    cmm_free_list = malloc(cmm_max_free_lists * sizeof(void *));
    assert(cmm_free_list);
    memset(cmm_free_list, 0, cmm_max_free_lists*sizeof(void *));

    cmm_bittable = malloc(cmm_bittable_size>>3);
    assert(cmm_bittable);
    memset(cmm_bittable, 0, cmm_bittable_size>>3);

    cmm_bitmalloc = malloc(cmm_bittable_size>>3);
    assert(cmm_bitmalloc);
    memset(cmm_bitmalloc, 0, cmm_bittable_size>>3);

    cmm_arena = mmap(NULL, pgsize + mem_arena_size + pgsize, PROT_READ|PROT_WRITE,
		     MAP_ANON|MAP_PRIVATE, 0, 0);
    assert(MAP_FAILED  != cmm_arena);
    mprotect(cmm_arena, pgsize, PROT_NONE);
    mprotect(cmm_arena + aligned, pgsize, PROT_NONE);
    set_bit(cmm_arena, 0, cmm_bittable);
    cmm_add_to_list(&cmm_free_list[0], cmm_arena);

    /* first bit means that table is in use, multi-arena management */
    /* SETBIT(cmm_bittable, 0); */

    return cmm_arena;
}

void *
cmm_malloc(int size)
{
    int i, list, slist;
    void *chunk = NULL, *temp;

    i = Mem_min_unit; list = cmm_max_free_lists-1;
    while (i < size + Overrun_bytes) {
	i<<=1;
	list--;
    }
    if (list < 0) goto out;

    /* try to find a larger entry to split */
    slist = list;
    while (slist >= 0) {
	if (cmm_free_list[slist] != NULL)
	    break;
	slist--;
    }
    if (slist < 0) goto out;

    /* split larger entry */
    while (slist != list) {
	temp = cmm_free_list[slist];

	/* remove from bigger list */
	assert(!testbit(temp, slist, cmm_bitmalloc));
	clearbit(temp, slist, cmm_bittable);
	cmm_remove_from_list(temp, cmm_free_list[slist]);
	assert(temp != cmm_free_list[slist]);

	/* done with bigger list */
	slist++;

	/* add to smaller list */
	assert(!testbit(temp, slist, cmm_bitmalloc));
	set_bit(temp, slist, cmm_bittable);
	cmm_add_to_list(&cmm_free_list[slist], temp);
	assert(cmm_free_list[slist] == temp);

	/* split in 2 */
	temp += mem_arena_size >> slist;
	assert(!testbit(temp, slist, cmm_bitmalloc));
	set_bit(temp, slist, cmm_bittable);
	cmm_add_to_list(&cmm_free_list[slist], temp);
	assert(cmm_free_list[slist] == temp);

	assert(temp-(mem_arena_size>>slist) == mybuddy(temp, slist));
    }

    /* peel off memory to hand back */
    chunk = cmm_free_list[list];
    assert(testbit(chunk, list, cmm_bittable));
    set_bit(chunk, list, cmm_bitmalloc);
    cmm_remove_from_list(chunk, cmm_free_list[list]);

    assert(chunk >= cmm_arena && chunk < cmm_arena+mem_arena_size);

#ifdef CMM_DEBUG
    for (i = 0; i < cmm_bittable_size; i++) {
	if (TESTBIT(cmm_bitmalloc,i)) {
	    assert(TESTBIT(cmm_bittable,i));
	}
    }
#endif

 out:
    return chunk;
}

static int cmm_free_calls = 0;

int
cmm_free(void *lamb)
{
    int list;
    void *buddy;
#ifdef CMM_DEBUG
    int i;
#endif
    cmm_free_calls++;

    assert(lamb >= cmm_arena && lamb < cmm_arena+mem_arena_size);

    list = getlist(lamb);
    assert(testbit(lamb, list, cmm_bittable));
    clearbit(lamb, list, cmm_bitmalloc);
    cmm_add_to_list(&cmm_free_list[list], lamb);

    while (NULL != (buddy = mybuddy(lamb, list))) {
	assert(lamb == mybuddy(buddy, list));

	assert(lamb);
	assert(!testbit(lamb, list, cmm_bitmalloc));
	clearbit(lamb, list, cmm_bittable);
	cmm_remove_from_list(lamb, cmm_free_list[list]);
	assert(!testbit(lamb, list, cmm_bitmalloc));
	clearbit(buddy, list, cmm_bittable);
	cmm_remove_from_list(buddy, cmm_free_list[list]);

	list--;

	if (lamb > buddy) lamb = buddy;

	assert(!testbit(lamb, list, cmm_bitmalloc));
	set_bit(lamb, list, cmm_bittable);
	cmm_add_to_list(&cmm_free_list[list], lamb);
	assert(cmm_free_list[list] == lamb);
    }

#ifdef CMM_DEBUG
    for (i = 0; i < cmm_bittable_size; i++) {
	if (TESTBIT(cmm_bitmalloc,i)) {
	    assert(TESTBIT(cmm_bittable,i));
	}
    }
#endif

    return 0;
}

int
cmm_usable_size(void *lamb)
{
    int list = getlist(lamb);
    int size;

    assert(lamb >= cmm_arena && lamb < cmm_arena+mem_arena_size);
    assert(testbit(lamb, list, cmm_bittable));

    size = mem_arena_size/(1<<list);

    return size;
}

void *
cmm_realloc(void *lamb, int size)
{
    void *temp;
    int oldsize;

    oldsize = cmm_usable_size(lamb);

    if ((size > oldsize/2) && (size <= oldsize))
        return lamb;

    if ((size < Mem_min_unit) && (Mem_min_unit == oldsize))
        return lamb;

    temp = lamb;
    lamb = cmm_malloc(size);

    if (NULL == lamb)
        return NULL;

    size = MIN(size, oldsize);
    memcpy(lamb, temp, size);

    cmm_free(temp);

    return lamb;
}

typedef struct _cmm_list cmm_list;
struct _cmm_list {
    cmm_list *next;
    cmm_list **p_next;
};

static void
cmm_add_to_list(void **list, void *lamb)
{
    cmm_list *temp;
#ifdef CMM_DEBUG
    cmm_list *temp2;
#endif

    assert(list >= cmm_free_list &&
	   list < cmm_free_list + cmm_max_free_lists);
    assert(lamb >= cmm_arena &&
	   lamb < cmm_arena + mem_arena_size);

    temp = (cmm_list *)lamb;
    temp->next = *(cmm_list **)list;
    assert(temp->next == NULL ||
	   ((void *)temp->next >= cmm_arena &&
	    (void *)temp->next < cmm_arena+mem_arena_size));
    temp->p_next = (cmm_list **)list;

    if (NULL != temp->next) {
	assert((void **)temp->next->p_next == list);
	temp->next->p_next = &(temp->next);
    }

    *list = lamb;

#ifdef CMM_DEBUG
    for (temp = *list; temp != NULL; temp = temp->next) {
	if (NULL != temp->next)
	    assert(temp->next->p_next == &temp->next);
	if (lamb == temp) temp2 = lamb;
    }
    assert (NULL != temp2);
#endif
}

static void
cmm_remove_from_list(void *lamb, void *list)
{
    cmm_list *temp, *temp2;

#ifdef CMM_DEBUG
    temp2 = NULL;

    for (temp = list; temp != NULL; temp = temp->next) {
	if (NULL != temp->next)
	    assert(temp->next->p_next == &temp->next);
	if (lamb == temp) temp2 = lamb;
    }
    assert (NULL != temp2);
#endif

    temp = (cmm_list *)lamb;
    if (NULL != temp->next)
	temp->next->p_next = temp->p_next;
    *temp->p_next = temp->next;

    if (NULL == temp->next)
	return;

    temp2 = temp->next;
    assert((((void **)temp2->p_next >= cmm_free_list) &&
	    ((void **)temp2->p_next < cmm_free_list + cmm_max_free_lists))
	   ||
	   (((void *)temp2->p_next >= cmm_arena) &&
	    ((void *)temp2->p_next < cmm_arena + mem_arena_size)));
}

static void *
mybuddy(void *lamb, int list)
{
    int index;
    void *chunk = NULL;

    index = (1<<list) + ((lamb-cmm_arena)/(mem_arena_size>>list));
    index ^= 1;

    if (TESTBIT(cmm_bittable,index) &&
	!TESTBIT(cmm_bitmalloc,index)) {
	chunk = cmm_arena + ((index & ((1<<list)-1)) * (mem_arena_size>>list));
    }

    return chunk;
}

static int
getlist(void *lamb)
{
    int index, list;

    list = cmm_max_free_lists-1;
    index = (mem_arena_size + lamb - cmm_arena) / Mem_min_unit;

    while (index) {
	if (TESTBIT(cmm_bittable,index)) {
	    break;
	}
	assert(!(index & 1));
	index >>= 1;
	list--;
    }

    return list;
}

static int
testbit(void *lamb, int list, u_int8 *table)
{
    int index;

    assert(list < cmm_max_free_lists && list >= 0);
    assert(!((lamb-cmm_arena)&((mem_arena_size>>list)-1)));

    index = (1<<list) + ((lamb - cmm_arena) / (mem_arena_size>>list));

    assert(index > 0 && index < cmm_bittable_size);

    return TESTBIT(table,index);
}

static void
clearbit(void *lamb, int list, u_int8 *table)
{
    int index;

    assert(list < cmm_max_free_lists && list >= 0);
    assert(!((lamb-cmm_arena)&((mem_arena_size>>list)-1)));

    index = (1<<list) + ((lamb - cmm_arena) / (mem_arena_size>>list));

    assert(index > 0 && index < cmm_bittable_size);

    assert(TESTBIT(table,index));
    CLEARBIT(table,index);
}

static void
set_bit(void *lamb, int list, u_int8 *table)
{
    int index;

    assert(list < cmm_max_free_lists && list >= 0);
    assert(!((lamb-cmm_arena)&((mem_arena_size>>list)-1)));

    index = (1<<list) + ((lamb - cmm_arena) / (mem_arena_size>>list));

    assert(index > 0 && index < cmm_bittable_size);

    assert(!TESTBIT(table,index));
    SETBIT(table,index);
}

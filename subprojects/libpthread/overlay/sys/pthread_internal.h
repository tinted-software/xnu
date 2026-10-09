/*
 * XNU's <sys/pthread_internal.h> is an opaque blob sized for uthread.uu_kwe.
 * Apple's pthread kext needs the real ksyn_waitq_element layout, but we must
 * not pull kern/kern_internal.h from here: user.h includes this header in the
 * middle of defining struct uthread.
 */
#ifndef _KSYN_WAITQ_ELEMENT_DEFINED
#define _KSYN_WAITQ_ELEMENT_DEFINED
#include <sys/queue.h>
#include <kern/kern_types.h>
struct ksyn_waitq_element {
	TAILQ_ENTRY(ksyn_waitq_element) kwe_list;
	void *          kwe_kwqqueue;
	thread_t        kwe_thread;
	uint16_t        kwe_state;
	uint16_t        kwe_flags;
	uint32_t        kwe_lockseq;
	uint32_t        kwe_count;
	uint32_t        kwe_psynchretval;
	void            *kwe_uth;
};
typedef struct ksyn_waitq_element * ksyn_waitq_element_t;
#endif

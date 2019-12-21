#include "stdlib/assert.h"
#include "stdlib/string.h"

#include "kernel/asm.h"
#include "kernel/thread.h"

#include "kernel/misc/gdt.h"
#include "kernel/misc/util.h"

#include "kernel/lib/memory/map.h"
#include "kernel/lib/memory/layout.h"
#include "kernel/lib/console/terminal.h"

#if LAB >= 7
// arguments are passed via `rdi', `rsi', `rdx' (see IA-32 calling conventions)
static void thread_foo(struct task *thread, thread_func_t foo, void *arg)
{
	assert(thread != NULL && foo != NULL);

	foo(arg);

	task_destroy(thread);

	// call schedule
	asm volatile ("int3");
}
#endif

/*
 * LAB8 Instruction:
 * 1. create new task
 * 2. allocate and map stack (hint: you can use `USER_STACK_TOP')
 * 3. pass function arguments via `rdi, rsi, rdx' (store `data' on new stack)
 * 4. setup segment registers
 * 5. setup instruction pointer and stack pointer
 */
// Don't override stack (don't use large `data')
struct task *thread_create(const char *name, thread_func_t foo, const uint8_t *data, size_t size)
{
	struct page *stack;
	struct task *task;

	if ((task = task_new(name)) == NULL)		// create new task
		goto cleanup;

	if ((stack = page_alloc()) == NULL) {		// create stack for current thread
		terminal_printf("Can't create thread `%s': no memory for stack\n", name);
		goto cleanup;
	}

	// map PML4 to created stack
	if (page_insert(task->pml4, stack, USER_STACK_TOP-PAGE_SIZE, PTE_U | PTE_W) != 0) {
		terminal_printf("Can't create thread `%s': page_insert(stack) failed\n", name);
		goto cleanup;
	}

	// prepare stack and arguments	
	uint8_t *stack_top = (uint8_t *)USER_STACK_TOP;

	uintptr_t cr3 = rcr3();		// rest CR3: movq cr3, value
	lcr3(PADDR(task->pml4));	// save CR3 by new address of PML4 in current task

	if (data != NULL)
	{
		// pointer to data must be ptr aligned, here we use macro ROUND_DOWN
		void *data_ptr = (void *)ROUND_DOWN((uintptr_t)(stack_top-size), sizeof(void *));

		memcpy(data_ptr, data, size);	// copy our data
		data = stack_top = data_ptr;	// save pointer of stack_top and data
	}

	// Set return address
	stack_top -= sizeof(uintptr_t);
	*(uintptr_t *)stack_top = (uintptr_t)0;		// Set return value

	// Notice that: Process transfering arguments to function by using registers RDI, RSI, RDX, R10, R8, R9
	// In this case, we tranfer arguments to function thread_foo:
	// but 1st and 2nd args are from kernel space (not from stack), so we can save direct pointers
	task->context.gprs.rdi = (uintptr_t)task;
	task->context.gprs.rsi = (uintptr_t)foo;
	task->context.gprs.rdx = (uintptr_t)data;

	lcr3(cr3);		// save CR3

	// start all segment registers
	task->context.cs = GD_KT;
	task->context.ds = GD_KD;
	task->context.es = GD_KD;
	task->context.ss = GD_KD;

	task->context.rip = (uintptr_t)thread_foo;		// instruction pointer
	task->context.rsp = (uintptr_t)stack_top;		// stack pointer

	return task;

cleanup:		// first stuffs at all
	if (task != NULL)
		task_destroy(task);

	return NULL;
}

// LAB8 Instruction: just change `state', so scheduler can run this thread
void thread_run(struct task *thread)
{
	assert(thread->state == TASK_STATE_DONT_RUN);
	thread->state = TASK_STATE_READY;
}

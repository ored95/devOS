#include "kernel/task.h"
#include "kernel/syscall.h"
#include "kernel/lib/memory/map.h"
#include "kernel/lib/memory/mmu.h"
#include "kernel/lib/memory/layout.h"

#include "stdlib/assert.h"
#include "stdlib/string.h"
#include "stdlib/syscall.h"

#include "kernel/lib/console/terminal.h"

// LAB5 Instruction:
// - find page, virtual address `va' belongs to. Use page_lookup
// - insert it into `dest->pml4' and `src->pml4' if needed

// __attribute__((unused))	/* deleting */
static int task_share_page(struct task *dest, struct task *src, void *va, unsigned perm)
{
	uintptr_t va_addr = (uintptr_t)va;
	struct page *p = page_lookup(src->pml4, va_addr, NULL);
	assert(p != NULL);

	if ((perm & PTE_W) != 0 || (perm & PTE_COW) != 0) {
		perm = (perm | PTE_COW) & ~PTE_W;
		if (page_insert(src->pml4, p, va_addr, perm) != 0)
			return -1;
		if (page_insert(dest->pml4, p, va_addr, perm) != 0)
			return -1;
	} else {
		if (page_insert(dest->pml4, p, va_addr, perm) != 0)
			return -1;
	}

	terminal_printf("share page %p (va: %p): refs: %d\n", p, va, p->ref);

	return 0;
}

// LAB5 Instruction:
// - create new task, copy context, setup return value
//
// - share pages:
// - check all entries inside pml4 before `USER_TOP'
// - check all entrins inside page directory pointer size NPDP_ENTRIES
// - check all entries inside page directory size NPD_ENTRIES
// - check all entries inside page table and share if present NPT_ENTRIES
//
// - mark new task as `ready'
// - return new task id
// __attribute__((unused))
static int sys_fork(struct task *task)
{
	struct task *child = task_new("child-process");

	if (child == NULL)
		return -1;
	child->context = task->context;
	child->context.gprs.rax = 0; 		// return value of child (pid parent != 0)

	// Save all PML4
	for (uint16_t i = 0; i <= PML4_IDX(USER_TOP); i++) {
		// page map level 4 entry
		uintptr_t pdpe_pa = PML4E_ADDR(task->pml4[i]);

		if ((task->pml4[i] & PML4E_P) == 0)		// check present bit
			continue;

		// page directory pointer entry
		pdpe_t *pdpe = VADDR(pdpe_pa);
		for (uint16_t j = 0; j < NPDP_ENTRIES; j++) {
			uintptr_t pde_pa = PDPE_ADDR(pdpe[j]);

			if ((pdpe[j] & PDPE_P) == 0)		// check present bit
				continue;

			// page directory entry
			pde_t *pde = VADDR(pde_pa);
			for (uint16_t k = 0; k < NPD_ENTRIES; k++) {
				uintptr_t pte_pa = PTE_ADDR(pde[k]);

				if ((pde[k] & PDE_P) == 0)		// check present bit
					continue;

				// page table entry
				pte_t *pte = VADDR(pte_pa);
				for (uint16_t l = 0; l < NPT_ENTRIES; l++) {
					if ((pte[l] & PTE_P) == 0)	// check present bit
						continue;

					unsigned perm = pte[l] & PTE_FLAGS_MASK;	// receive 12 low bits of PTE page, check last bit permition
					if (task_share_page(child, task, PAGE_ADDR(i, j, k, l, 0), perm) != 0) {	// check sharable page for current task
						task_destroy(child);
						return -1;
					}
				}
			}
		}
	}

	child->state = TASK_STATE_READY;

	return child->id;
}

// LAB5 Instruction:
// - implement `puts', `exit', `fork' and `yield' syscalls
// - you can get syscall number from `rax'
// - return value also should be passed via `rax'
void syscall(struct task *task)
{
	enum syscall syscall = task->context.gprs.rax;		// index syscall is saved in GPRS.RAX
	int64_t ret = 0;

	switch (syscall) {
	case SYSCALL_PUTS:
		terminal_printf("task [%d]: %s", task->id, (char *)task->context.gprs.rbx);
		break;
	case SYSCALL_EXIT:
		terminal_printf("task [%d] exited with value `%d'\n",
				task->id, task->context.gprs.rbx);
		task_destroy(task);
		return schedule();
	case SYSCALL_FORK:
		ret = sys_fork(task);
		break;
	case SYSCALL_YIELD:
		return schedule();
	default:
		panic("unknown syscall `%u'\n", syscall);
	}

	task->context.gprs.rax = ret;		// only use for FORK
	task_run(task);
}

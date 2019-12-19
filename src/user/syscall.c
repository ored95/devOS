#include <stdint.h>

#include "stdlib/syscall.h"

static int64_t syscall(enum syscall syscall, uint64_t arg1, uint64_t arg2,
		       uint64_t arg3, uint64_t arg4, uint64_t arg5)
{
	int64_t ret;

	// execute system call
	asm volatile("int %1\n"
		: "=a" (ret)
		: "i" (INTERRUPT_VECTOR_SYSCALL),	// system call INT34 here
		  "a" (syscall),	// RAX
		  "b" (arg1),		// RBX
		  "c" (arg2),		// RCX
		  "d" (arg3),		// RDX
		  "D" (arg4),		// RDI
		  "S" (arg5)		// RSI
		: "cc", "memory");

	return ret;
}

void sys_puts(const char *string)
{
	return (void)syscall(SYSCALL_PUTS, (uintptr_t)string, 0, 0, 0, 0);
}

void sys_exit(int ret)
{
	return (void)syscall(SYSCALL_EXIT, (int64_t)ret, 0, 0, 0, 0);
}

void sys_yield(void)
{
	return (void)syscall(SYSCALL_YIELD, 0, 0, 0, 0, 0);
}

int sys_fork(void)
{
	return syscall(SYSCALL_FORK, 0, 0, 0, 0, 0);
}

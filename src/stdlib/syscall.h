#ifndef __SYSCALL_H__
#define __SYSCALL_H__

#define INTERRUPT_VECTOR_SYSCALL 34

#ifndef __ASSEMBLER__
enum syscall {
	SYSCALL_PUTS	= 0,	// PUTS
	SYSCALL_EXIT	= 1,	// EXIT
	SYSCALL_FORK	= 2,	// FORK
	SYSCALL_YIELD	= 3,	// YIELD

	SYSCALL_LAST
};
#endif

#endif

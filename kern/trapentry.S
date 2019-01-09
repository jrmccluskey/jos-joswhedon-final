/* See COPYRIGHT for copyright information. */

#include <inc/mmu.h>
#include <inc/memlayout.h>
#include <inc/trap.h>
#include <kern/macro.h>

#include <kern/picirq.h>


###################################################################
# exceptions/interrupts
###################################################################

/* TRAPHANDLER defines a globally-visible function for handling a trap.
 * It pushes a trap number onto the stack, then jumps to _alltraps.
 * Use TRAPHANDLER for traps where the CPU automatically pushes an error code.
 *
 * You shouldn't call a TRAPHANDLER function from C, but you may
 * need to _declare_ one in C (for instance, to get a function pointer
 * during IDT setup).  You can declare the function with
 *   void NAME();
 * where NAME is the argument passed to TRAPHANDLER.
 */
#define TRAPHANDLER(name, num)						\
	.globl name;		/* define global symbol for 'name' */	\
	.type name, @function;	/* symbol type is function */		\
	.align 2;		/* align function definition */		\
	name:			/* function starts here */		\
	pushq $(num);							\
	jmp _alltraps

/* Use TRAPHANDLER_NOEC for traps where the CPU doesn't push an error code.
 * It pushes a 0 in place of the error code, so the trap frame has the same
 * format in either case.
 */
#define TRAPHANDLER_NOEC(name, num)					\
	.globl name;							\
	.type name, @function;						\
	.align 2;							\
	name:								\
	pushq $0;							\
	pushq $(num);							\
	jmp _alltraps

.text

/*
 * Lab 3: Your code here for generating entry points for the different traps.
   Find the PUSHA,POPA macros in kern/macro.h. Since amd64 doesn't support
   pusha,popa so you will find these macros handy.
 */

// General Trap Handlers
TRAPHANDLER_NOEC(mc_div_zero, T_DIVIDE);
TRAPHANDLER_NOEC(mc_debug, T_DEBUG);
TRAPHANDLER_NOEC(mc_nmi, T_NMI);
TRAPHANDLER_NOEC(mc_breakpoint, T_BRKPT);
TRAPHANDLER_NOEC(mc_overflow, T_OFLOW);
TRAPHANDLER_NOEC(mc_bounds, T_BOUND);
TRAPHANDLER_NOEC(mc_illegal_op, T_ILLOP);
TRAPHANDLER_NOEC(mc_device_na, T_DEVICE);
TRAPHANDLER(mc_double_fault, T_DBLFLT);
//TRAPHANDLER_NOEC(mc_coproc, 9);
TRAPHANDLER(mc_invalid_tss, T_TSS);
TRAPHANDLER(mc_seg_np, T_SEGNP);
TRAPHANDLER(mc_stack_ex, T_STACK);
TRAPHANDLER(mc_protec_fault, T_GPFLT);
TRAPHANDLER(mc_page_fault, T_PGFLT);
//TRAPHANDLER(mc_reserved, 15);
TRAPHANDLER_NOEC(mc_float_error, T_FPERR);
TRAPHANDLER(mc_alignment, T_ALIGN);
TRAPHANDLER_NOEC(mc_machine_check, T_MCHK);
TRAPHANDLER_NOEC(mc_simd_float, T_SIMDERR);
TRAPHANDLER_NOEC(mc_syscall, T_SYSCALL);

// IRQ Handlers
TRAPHANDLER_NOEC(mc_timer, IRQ_OFFSET + IRQ_TIMER);
TRAPHANDLER_NOEC(mc_kbd, IRQ_OFFSET + IRQ_KBD);
TRAPHANDLER_NOEC(mc_serial, IRQ_OFFSET+IRQ_SERIAL);
TRAPHANDLER_NOEC(mc_spurious, IRQ_OFFSET + IRQ_SPURIOUS);
TRAPHANDLER_NOEC(mc_ide, IRQ_OFFSET + IRQ_IDE);
TRAPHANDLER_NOEC(mc_error, IRQ_OFFSET + IRQ_ERROR);

TRAPHANDLER_NOEC(mc_default, T_DEFAULT);

/*
 * Lab 3: Your code here for _alltraps
 *
 * Hint: Be sure to review the x64 calling convention from lab1
 *       for how to pass a pointer to the trapframe.
 */

_alltraps:
	// TODO: Fix pushes and pops
	subq $8, %rsp
	movw %ds, (%rsp)
	subq $8, %rsp
	movw %es, (%rsp)
	PUSHA
	movw $GD_KD, %ax
	movw %ax, %ds
	movw %ax, %es
	movq %rsp, %rdi
	cli
	call trap
	POPA_
	movw (%rsp), %es
	addq $8, %rsp
	movw (%rsp), %ds
	addq $8, %rsp
	iret

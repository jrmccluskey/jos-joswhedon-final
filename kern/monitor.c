// Simple command-line kernel monitor useful for
// controlling the kernel and exploring the system interactively.

#include <inc/stdio.h>
#include <inc/string.h>
#include <inc/memlayout.h>
#include <inc/assert.h>
#include <inc/x86.h>

#include <kern/console.h>
#include <kern/monitor.h>
#include <kern/dwarf.h>
#include <kern/kdebug.h>
#include <kern/dwarf_api.h>
#include <kern/trap.h>

#define CMDBUF_SIZE	80	// enough for one VGA text line


struct Command {
	const char *name;
	const char *desc;
	// return -1 to force monitor to exit
	int (*func)(int argc, char** argv, struct Trapframe* tf);
};

static struct Command commands[] = {
	{ "help", "Display this list of commands", mon_help },
	{ "kerninfo", "Display information about the kernel", mon_kerninfo },
	{ "backtrace", "Backtrace through the stack frame", mon_backtrace}
};
#define NCOMMANDS (sizeof(commands)/sizeof(commands[0]))

/***** Implementations of basic kernel monitor commands *****/

int
mon_help(int argc, char **argv, struct Trapframe *tf)
{
	int i;

	for (i = 0; i < NCOMMANDS; i++)
		cprintf("%s - %s\n", commands[i].name, commands[i].desc);
	return 0;
}

int
mon_kerninfo(int argc, char **argv, struct Trapframe *tf)
{
	extern char _start[], entry[], etext[], edata[], end[];

	cprintf("Special kernel symbols:\n");
	cprintf("  _start                  %08x (phys)\n", _start);
	cprintf("  entry  %08x (virt)  %08x (phys)\n", entry, entry - KERNBASE);
	cprintf("  etext  %08x (virt)  %08x (phys)\n", etext, etext - KERNBASE);
	cprintf("  edata  %08x (virt)  %08x (phys)\n", edata, edata - KERNBASE);
	cprintf("  end    %08x (virt)  %08x (phys)\n", end, end - KERNBASE);
	cprintf("Kernel executable memory footprint: %dKB\n",
		ROUNDUP(end - entry, 1024) / 1024);
	return 0;
}
/* Helper method for printinf out Ripdebug info with proper formatting
 * Input: Ripdebuginto pointer, pointer to address in bootstack
 * Output: void
 */
void print_rip(struct Ripdebuginfo * pointer, uint64_t * ptr) {
	cprintf("    %s:", pointer->rip_file);
	cprintf("%d: ", pointer->rip_line);
	cprintf("%.*s+", pointer->rip_fn_namelen, pointer->rip_fn_name);
	cprintf("%016llx ", ptr[1] - pointer->rip_fn_addr);
	cprintf("args:%d ", pointer->rip_fn_narg);
	Dwarf_Half regnum = pointer->reg_table.cfa_rule.dw_regnum;
	uint64_t cfa;
	if(regnum == 6) {
		cfa = ptr[0] + pointer->reg_table.cfa_rule.dw_offset;
	} else if(regnum == 7) {
		cfa = read_rsp();
	}
	for(int i = 0; i < pointer->rip_fn_narg; i++) {
		uint64_t offset_adr = cfa + pointer->offset_fn_arg[i];
		volatile uintptr_t offset_pointer = offset_adr;
		uint32_t *off_ptr = (uint32_t *) offset_pointer;
		cprintf("%016llx ", off_ptr[0]);
	}
	cprintf("\n");
}

int
mon_backtrace(int argc, char **argv, struct Trapframe *tf)
{
	// Print starting message
	cprintf("Stack backtrace:\n");
	// Initialize variables
	struct Ripdebuginfo ripped;
	struct Ripdebuginfo * pointer = &ripped;
	// Get rbp from function, convert into pointer
	uint64_t rbp = read_rbp();
	// Get rip using inline asm
	uint64_t rip_value;
	__asm __volatile("leaq (%%rip), %0" : "=r" (rip_value)::"cc","memory");
	// Print header
	cprintf("rbp %016llx  rip %016llx\n", rbp, rip_value);
	// Get debug info from rip and print
	debuginfo_rip(rip_value, pointer);
	// Print base case info 
	cprintf("    %s:", pointer->rip_file);
	cprintf("%d: ", pointer->rip_line);
	cprintf("%.*s+", pointer->rip_fn_namelen, pointer->rip_fn_name);
	cprintf("%016llx ", rip_value - pointer->rip_fn_addr);
	cprintf("args:%d ", pointer->rip_fn_narg);
	Dwarf_Half regnum = pointer->reg_table.cfa_rule.dw_regnum;
	uint64_t cfa;
	if(regnum == 6) {
		cfa = rbp + pointer->reg_table.cfa_rule.dw_offset;
	} else if(regnum == 7) {
		cfa = read_rsp();
	}
	for(int i = 0; i < pointer->rip_fn_narg; i++) {
		uint64_t offset_adr = cfa + pointer->offset_fn_arg[i];
		volatile uintptr_t offset_middleman = offset_adr;
		uint32_t *off_ptr = (uint32_t *) offset_middleman;
		cprintf("%016llx ", off_ptr[i]);
	}
	cprintf("\n");

	// Set up rbp_pointer for debug info
	volatile uintptr_t rbp_pointer = rbp;
	uint64_t *ptr = (uint64_t *)rbp_pointer;
	// Loop through rbp values, stop before printing 0x0
	while(ptr[0] != 0x0) {
		debuginfo_rip(ptr[1], pointer);
		cprintf("rbp %016llx  rip %016llx\n", ptr[0], ptr[1]);
		print_rip(pointer, ptr);
		rbp = (uint64_t) ptr[0];
		rbp_pointer = rbp;
		ptr = (uint64_t *)rbp_pointer;
	}
	return 0;
}



/***** Kernel monitor command interpreter *****/

#define WHITESPACE "\t\r\n "
#define MAXARGS 16

static int
runcmd(char *buf, struct Trapframe *tf)
{
	int argc;
	char *argv[MAXARGS];
	int i;

	// Parse the command buffer into whitespace-separated arguments
	argc = 0;
	argv[argc] = 0;
	while (1) {
		// gobble whitespace
		while (*buf && strchr(WHITESPACE, *buf))
			*buf++ = 0;
		if (*buf == 0)
			break;

		// save and scan past next arg
		if (argc == MAXARGS-1) {
			cprintf("Too many arguments (max %d)\n", MAXARGS);
			return 0;
		}
		argv[argc++] = buf;
		while (*buf && !strchr(WHITESPACE, *buf))
			buf++;
	}
	argv[argc] = 0;

	// Lookup and invoke the command
	if (argc == 0)
		return 0;
	for (i = 0; i < NCOMMANDS; i++) {
		if (strcmp(argv[0], commands[i].name) == 0)
			return commands[i].func(argc, argv, tf);
	}
	cprintf("Unknown command '%s'\n", argv[0]);
	return 0;
}

void
monitor(struct Trapframe *tf)
{
	char *buf;

	cprintf("Welcome to the JOS kernel monitor!\n");
	cprintf("Type 'help' for a list of commands.\n");

	if (tf != NULL)
		print_trapframe(tf);

	while (1) {
		buf = readline("K> ");
		if (buf != NULL)
			if (runcmd(buf, tf) < 0)
				break;
	}
}

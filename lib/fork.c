// implement fork from user space

#include <inc/string.h>
#include <inc/lib.h>

// PTE_COW marks copy-on-write page table entries.
// It is one of the bits explicitly allocated to user processes (PTE_AVAIL).
#define PTE_COW		0x800

//
// Custom page fault handler - if faulting page is copy-on-write,
// map in our own private writable copy.
//
static void
pgfault(struct UTrapframe *utf)
{
	void *addr = (void *) utf->utf_fault_va;
	uint32_t err = utf->utf_err;
	int r;

	// Check that the faulting access was (1) a write, and (2) to a
	// copy-on-write page.  If not, panic.
	// Hint:
	//   Use the read-only page table mappings at uvpt
	//   (see <inc/memlayout.h>).

	// LAB 4: Your code here.
	pte_t entry = uvpt[VPN(addr)];
	int perms = entry & PTE_SYSCALL;
	if(!(err & FEC_WR) || !(perms & PTE_COW)) {
		panic("Inappropriate permissions!");
		return;
	}

	// Allocate a new page, map it at a temporary location (PFTEMP),
	// copy the data from the old page to the new page, then move the new
	// page to the old page's address.
	// Hint:
	//   You should make three system calls.
	//   No need to explicitly delete the old page's mapping.

	// LAB 4: Your code here.
	int alloc_check = sys_page_alloc(0, PFTEMP, PTE_P | PTE_W | PTE_U);
	if(alloc_check < 0) panic("Page alloc failed!");
	
	uint64_t rounded = ROUNDDOWN((uint64_t)addr, PGSIZE);
	memmove(PFTEMP, (void *)rounded, PGSIZE);

	int map_check = sys_page_map(0, PFTEMP, 0, (void *) rounded, PTE_P | PTE_W | PTE_U);
	if(map_check < 0) panic("Mapping page to PFTEMP failed in pgfault!");

	int unmap_check = sys_page_unmap(0, PFTEMP);
	if(unmap_check < 0) panic("PFTEMP unmap failed!");

	return;
}

//
// Map our virtual page pn (address pn*PGSIZE) into the target envid
// at the same virtual address.  If the page is writable or copy-on-write,
// the new mapping must be created copy-on-write, and then our mapping must be
// marked copy-on-write as well.  (Exercise: Why do we need to mark ours
// copy-on-write again if it was already copy-on-write at the beginning of
// this function?)
//
// Returns: 0 on success, < 0 on error.
// It is also OK to panic on error.
//
static int
duppage(envid_t envid, unsigned pn)
{
	int r;

	// LAB 4: Your code here.
	uint64_t address = pn * PGSIZE;
	pte_t entry = uvpt[pn];
	int perms = entry & PTE_USER;
	int check;
	if((perms & PTE_W) || (perms & PTE_COW)) {
		perms &= ~PTE_W;
		perms |= PTE_COW;
		check = sys_page_map(0, (void *)address, envid, (void *)address, perms);
		if(check < 0) panic("Mapping failed!");
		r = sys_page_map(0, (void *)address, 0, (void *)address, perms);
		if(r < 0) panic("Restoring COW failed!");
	} else {
		check = sys_page_map(0, (void *)address, envid, (void *)address, perms);
		if(check < 0) return -1;
	}
	return 0;
}

//
// User-level fork with copy-on-write.
// Set up our page fault handler appropriately.
// Create a child.
// Copy our address space and page fault handler setup to the child.
// Then mark the child as runnable and return.
//
// Returns: child's envid to the parent, 0 to the child, < 0 on error.
// It is also OK to panic on error.
//
// Hint:
//   Use uvpd, uvpt, and duppage.
//   Remember to fix "thisenv" in the child process.
//   Neither user exception stack should ever be marked copy-on-write,
//   so you must allocate a new page for the child's user exception stack.
//
envid_t
fork(void)
{
	set_pgfault_handler(pgfault);
	envid_t child_id = sys_exofork();
	int check;
	if(child_id < 0) panic("Exofork failed in fork!");
	
	// Child Case
	if(child_id == 0) {
		thisenv = &envs[ENVX(sys_getenvid())];
		return 0;
	}	
	
	// Parent Case
	// Copy pages
	uintptr_t addr;
	extern unsigned char end[];
	for(addr = (uintptr_t)UTEXT; addr < (uintptr_t)UTOP; addr += PGSIZE) {
		int perms = (uvpml4e[VPML4E(addr)] & PTE_P);
		if(perms == 0) {
			addr += (NPDPENTRIES  * NPDENTRIES * PGSIZE);
			continue;
		}

		perms = (uvpde[VPDPE(addr)] & PTE_P);
		if(perms == 0) {
			addr +=(NPDENTRIES * NPTENTRIES * PGSIZE);
			continue;
		}

		perms = (uvpd[VPD(addr)] & PTE_P);
		if(perms == 0){
			addr+= (NPTENTRIES * PGSIZE);
			continue;
		}

		perms = (uvpt[PGNUM(addr)] & PTE_P);
		if(perms && (addr != (UXSTACKTOP - PGSIZE))) duppage(child_id, PGNUM(addr));
	} 

	// Map exception stack
	check = sys_page_alloc(sys_getenvid(), PFTEMP, PTE_P|PTE_U|PTE_W);
	if(check < 0) panic("Couldn't alloc PFTEMP!");

	memcpy(PFTEMP, (void *)(UXSTACKTOP - PGSIZE), PGSIZE);

	check = sys_page_map(sys_getenvid(), PFTEMP, child_id, (void *)(UXSTACKTOP - PGSIZE), PTE_P|PTE_U|PTE_W);
	if(check < 0) panic("Couldn't map values to child stack!");

	check = sys_page_unmap(sys_getenvid(), PFTEMP);
	if(check < 0) panic("Failed to unmap PFTEMP!");

	// Set User Page Fault Entrypoint
	check = sys_page_alloc(child_id, (void *)(UXSTACKTOP - PGSIZE), PTE_P|PTE_U|PTE_W);
	if(check < 0) panic("Couldn't allocate exception stack!");

	extern void _pgfault_upcall(void);
	check = sys_env_set_pgfault_upcall(child_id, _pgfault_upcall);
	if(check < 0) panic("Failed to set upcall in child!");

	// Mark child as runnable
	check = sys_env_set_status(child_id, ENV_RUNNABLE);
	if(check < 0) {
		panic("Cannot set child as runnable!");
		return -1;
	} else {
		return child_id;
	}
}

// Challenge!
int
sfork(void)
{
	panic("sfork not implemented");
	return -E_INVAL;
}

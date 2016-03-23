#include "win32_x86.h"
#include <windows.h>
#include <assert.h>

namespace gdb {

#ifndef __x86_64__

/* An array of offset mappings into a Win32 Context structure.
This is a one-to-one mapping which is indexed by gdb's register
numbers.  It retrieves an offset into the context structure where
the 4 byte register is located.
An offset value of -1 indicates that Win32 does not provide this
register in it's CONTEXT structure.  In this case regptr will return
a pointer into a dummy register.  */
#define context_offset(x) ((int)&(((CONTEXT *)NULL)->x))
static const int mappings[] = {
	context_offset(Eax),
	context_offset(Ecx),
	context_offset(Edx),
	context_offset(Ebx),
	context_offset(Esp),
	context_offset(Ebp),
	context_offset(Esi),
	context_offset(Edi),
	context_offset(Eip),
	context_offset(EFlags),
	context_offset(SegCs),
	context_offset(SegSs),
	context_offset(SegDs),
	context_offset(SegEs),
	context_offset(SegFs),
	context_offset(SegGs),
	context_offset(FloatSave.RegisterArea[0 * 10]),
	context_offset(FloatSave.RegisterArea[1 * 10]),
	context_offset(FloatSave.RegisterArea[2 * 10]),
	context_offset(FloatSave.RegisterArea[3 * 10]),
	context_offset(FloatSave.RegisterArea[4 * 10]),
	context_offset(FloatSave.RegisterArea[5 * 10]),
	context_offset(FloatSave.RegisterArea[6 * 10]),
	context_offset(FloatSave.RegisterArea[7 * 10]),
	context_offset(FloatSave.ControlWord),
	context_offset(FloatSave.StatusWord),
	context_offset(FloatSave.TagWord),
	context_offset(FloatSave.ErrorSelector),
	context_offset(FloatSave.ErrorOffset),
	context_offset(FloatSave.DataSelector),
	context_offset(FloatSave.DataOffset),
	context_offset(FloatSave.ErrorSelector),
	/* XMM0-7 */
	context_offset(ExtendedRegisters[10 * 16]),
	context_offset(ExtendedRegisters[11 * 16]),
	context_offset(ExtendedRegisters[12 * 16]),
	context_offset(ExtendedRegisters[13 * 16]),
	context_offset(ExtendedRegisters[14 * 16]),
	context_offset(ExtendedRegisters[15 * 16]),
	context_offset(ExtendedRegisters[16 * 16]),
	context_offset(ExtendedRegisters[17 * 16]),
	/* MXCSR */
	context_offset(ExtendedRegisters[24])
};
#undef context_offset

#else /* __x86_64__ */

#define context_offset(x) (offsetof (CONTEXT, x))
static const int mappings[] =
{
	context_offset(Rax),
	context_offset(Rbx),
	context_offset(Rcx),
	context_offset(Rdx),
	context_offset(Rsi),
	context_offset(Rdi),
	context_offset(Rbp),
	context_offset(Rsp),
	context_offset(R8),
	context_offset(R9),
	context_offset(R10),
	context_offset(R11),
	context_offset(R12),
	context_offset(R13),
	context_offset(R14),
	context_offset(R15),
	context_offset(Rip),
	context_offset(EFlags),
	context_offset(SegCs),
	context_offset(SegSs),
	context_offset(SegDs),
	context_offset(SegEs),
	context_offset(SegFs),
	context_offset(SegGs),
	context_offset(FloatSave.FloatRegisters[0]),
	context_offset(FloatSave.FloatRegisters[1]),
	context_offset(FloatSave.FloatRegisters[2]),
	context_offset(FloatSave.FloatRegisters[3]),
	context_offset(FloatSave.FloatRegisters[4]),
	context_offset(FloatSave.FloatRegisters[5]),
	context_offset(FloatSave.FloatRegisters[6]),
	context_offset(FloatSave.FloatRegisters[7]),
	context_offset(FloatSave.ControlWord),
	context_offset(FloatSave.StatusWord),
	context_offset(FloatSave.TagWord),
	context_offset(FloatSave.ErrorSelector),
	context_offset(FloatSave.ErrorOffset),
	context_offset(FloatSave.DataSelector),
	context_offset(FloatSave.DataOffset),
	context_offset(FloatSave.ErrorSelector)
	/* XMM0-7 */,
	context_offset(Xmm0),
	context_offset(Xmm1),
	context_offset(Xmm2),
	context_offset(Xmm3),
	context_offset(Xmm4),
	context_offset(Xmm5),
	context_offset(Xmm6),
	context_offset(Xmm7),
	context_offset(Xmm8),
	context_offset(Xmm9),
	context_offset(Xmm10),
	context_offset(Xmm11),
	context_offset(Xmm12),
	context_offset(Xmm13),
	context_offset(Xmm14),
	context_offset(Xmm15),
	/* MXCSR */
	context_offset(FloatSave.MxCsr)
};
#undef context_offset

#endif /* __x86_64__ */

X86Target::X86Target() : Target(sizeof(mappings) / sizeof(mappings[0]))
{
	_ctx.ContextFlags = CONTEXT_ALL;
	GetThreadContext(GetCurrentThread(), &_ctx);
	printf("esp: %x, ebp: %x, eip: %x, eax: %x, ebx: %x, ecx: %x, edx: %p, esi: %p, edi: %p, eflag: %x\n",
		_ctx.Esp, _ctx.Ebp, _ctx.Eip, _ctx.Eax, _ctx.Ebx, _ctx.Ecx, _ctx.Edx, _ctx.Esi, _ctx.Edi, _ctx.EFlags);
}

const std::string& X86Target::xml_core(void)
{
	static std::string desc;
	if (desc.size() == 0) {
		char buf[4096] = { 0 };
		FILE* fp = fopen("32bit-core.xml", "r");
		fread(buf, 1, sizeof(buf), fp);
		fclose(fp);
		desc = buf;
	}

	return desc;
}

int X86Target::rd_reg(int reg_no)
{
	if (reg_no > _num_regs)
		return 14;

	char* p = (char *)&_ctx;
	put_reg(*(addr_type* )(p + mappings[reg_no]));
	return 0;
}

int X86Target::wr_reg(int reg_no, addr_type value)
{
	if (reg_no > _num_regs)
		return 14;
	char* p = (char *)&_ctx;
	*(addr_type* )(p + mappings[reg_no]) = value;
	return 0;
}

int X86Target::rd_mem(addr_type addr)
{
	if (IsBadReadPtr((PVOID )addr, 1)) {
		return -1;
	}

	put_mem(*(char*)addr);
	return 0;
}

int X86Target::wr_mem(addr_type addr, char data)
{
	if (IsBadWritePtr((PVOID)addr, 1)) {
		return -1;
	}

	*((char*)addr) = data;
	return 0;
}

int X86Target::set_breakpoint(addr_type addr, size_type size)
{
	return -1;
}

int X86Target::del_breakpoint(addr_type addr, size_type size)
{
	return -1;
}

bool X86Target::has_breakpoint(addr_type addr, size_type size)
{
	return false;
}

int X86Target::query(const std::string& type)
{
	return -1;
}

} // namespace gdb {

#include <iostream>
#include <cstring>
#include <assert.h>
#include "gdbserver.h"
#include "win32_x86.h"

using namespace std;
using namespace gdb;

#define TEXT_START              (0x8394)
#define TEXT_SIZE               (8 * 4)
#define TEXT_END                (TEXT_START + TEXT_SIZE)
#define TEXT_BRANCH_TARGET      (0x83a0)

#define DATA_START              (0xa000)
#define DATA_SIZE               (16)
#define DATA_END                (DATA_START + DATA_SIZE)

enum ARMv7_RegisterNames {
	ARMv7_REG_R0 = 0,
	ARMv7_REG_R1, ARMv7_REG_R2, ARMv7_REG_R3, ARMv7_REG_R4,
	ARMv7_REG_R5, ARMv7_REG_R6, ARMv7_REG_R7, ARMv7_REG_R8,
	ARMv7_REG_R9, ARMv7_REG_R10, ARMv7_REG_R11, ARMv7_REG_R12,
	ARMv7_REG_SP, ARMv7_REG_LR, ARMv7_REG_PC, ARMv7_REG_F0,
	ARMv7_REG_F1, ARMv7_REG_F2, ARMv7_REG_F3, ARMv7_REG_F4,
	ARMv7_REG_F5, ARMv7_REG_F6, ARMv7_REG_F7, ARMv7_REG_FPS,
	ARMv7_REG_CPSR,

	ARMv7_NUM_REGS
};

/* TODO Move to .cc file and declare as extern */
static const std::string armv7_xml_core =
"<?xml version=\"1.0\"?>"
"<!DOCTYPE feature SYSTEM \"gdb-target.dtd\">"
"<feature name=\"org.gnu.gdb.arm.core\">"
"  <reg name=\"r0\"   bitsize=\"32\"/>"
"  <reg name=\"r1\"   bitsize=\"32\"/>"
"  <reg name=\"r2\"   bitsize=\"32\"/>"
"  <reg name=\"r3\"   bitsize=\"32\"/>"
"  <reg name=\"r4\"   bitsize=\"32\"/>"
"  <reg name=\"r5\"   bitsize=\"32\"/>"
"  <reg name=\"r6\"   bitsize=\"32\"/>"
"  <reg name=\"r7\"   bitsize=\"32\"/>"
"  <reg name=\"r8\"   bitsize=\"32\"/>"
"  <reg name=\"r9\"   bitsize=\"32\"/>"
"  <reg name=\"r10\"  bitsize=\"32\"/>"
"  <reg name=\"r11\"  bitsize=\"32\"/>"
"  <reg name=\"r12\"  bitsize=\"32\"/>"
"  <reg name=\"sp\"   bitsize=\"32\" type=\"data_ptr\"/>"
"  <reg name=\"lr\"   bitsize=\"32\"/>"
"  <reg name=\"pc\"   bitsize=\"32\" type=\"code_ptr\"/>"
"  <reg name=\"cpsr\" bitsize=\"32\" regnum=\"25\"/>"
"</feature>";

class FakeARMv7Context : public Target {
public:
    FakeARMv7Context()
    : Target(ARMv7_NUM_REGS)
    {
        static unsigned char text_mem_[] = {
            0x04, 0xb0, 0x2d, 0xe5,  /* 8394:  push  {fp}            */
            0x00, 0xb0, 0x8d, 0xe2,  /* 8398:  add   fp, sp, #0      */
            0x14, 0xd0, 0x4d, 0xe2,  /* 839c:  sub   sp, sp, #20     */
            0x08, 0x20, 0x1b, 0xe5,  /* 83a0:  ldr   r2, [fp, #-8]   */
            0x0c, 0x30, 0x1b, 0xe5,  /* 83a4:  ldr   r3, [fp, #-12]  */
            0x03, 0x30, 0x82, 0xe0,  /* 83a8:  add   r3, r2, r3      */
            0x10, 0x30, 0x0b, 0xe5,  /* 83ac:  str   r3, [fp, #-16]  */
            0xfa, 0xff, 0xff, 0xea,  /* 83b0:  b     83a0            */
        };
        text_mem = text_mem_;

        regs[ARMv7_REG_PC] = TEXT_START;
    }

	int rd_reg(int reg_no)
    {
        assert(0 <= reg_no && reg_no < ARMv7_NUM_REGS);
        put_reg(regs[reg_no]);
		return 0;
    }

	int wr_reg(int reg_no, addr_type value)
    {
        assert(0 <= reg_no && reg_no < ARMv7_NUM_REGS);
        regs[reg_no] = value;
		return 0;
    }

	int rd_mem(addr_type addr)
    {
        if (TEXT_START <= addr && addr <= TEXT_END) {
            addr -= TEXT_START;
            put_mem(text_mem[addr]);
        } else if (DATA_START <= addr && addr < DATA_END) {
            addr -= DATA_START;
            put_mem(data_mem[addr]);
        } else 
            put_mem(0);

		return 0;
    }

	int wr_mem(addr_type addr, char data)
    {
        if (DATA_START <= addr && addr < DATA_END) {
            addr -= DATA_START;
            data_mem[addr] = data;
            return 0;
        } else
            return -1;
    }

    int num_regs(void)
    {
        return ARMv7_NUM_REGS;
    }

    const std::string& xml_core(void)
    {
        return armv7_xml_core;
    }

	int set_breakpoint(addr_type addr, size_type size)
    {
        for (size_type i = 0; i < size; i ++) {
            assert(breakpoint_set.count(addr + i) == 0);
            breakpoint_set.insert(addr + i);
        }

		return 0;
    }

	int del_breakpoint(addr_type addr, size_type size)
    {
        for (size_type i = 0; i < size; i ++) {
            assert(breakpoint_set.count(addr + i) == 1);
            breakpoint_set.erase(addr + i);
        }

		return 0;
    }

	bool has_breakpoint(addr_type addr, size_type size)
    {
        int c = 0;
        for (size_type i = 0; i < size; i++)
            c += breakpoint_set.count(addr + i);
        return c > 0;
    }

	int query(const std::string& type)
	{
		return 0;
	}

public:
    uint32_t regs[ARMv7_NUM_REGS];

private:
    typedef std::set<addr_type> breakpoint_set_t;
    breakpoint_set_t breakpoint_set;

    unsigned char *text_mem;
    char data_mem[DATA_SIZE];
};

int
main(int argc, char **argv)
{
	WSADATA wsaData;
	WSAStartup(MAKEWORD(2, 0), &wsaData);
    FakeARMv7Context *ctx = new FakeARMv7Context();
	target_ptr ctx_ptr = target_ptr(new X86Target());
	// target_ptr ctx_ptr = target_ptr(ctx);

    Server server(ctx_ptr);

    // try {
        addr_type pc = TEXT_START;

        do {
            ctx->regs[ARMv7_REG_PC] = pc;
            server.update(pc);

            pc += 4;
            if (pc == TEXT_END)
                pc = TEXT_BRANCH_TARGET;
        } while (1);

    // } catch (gdb::exception &e) {
        //cerr << e.what() << endl;
        //exit(EXIT_FAILURE);
    // }

    return 0;
}

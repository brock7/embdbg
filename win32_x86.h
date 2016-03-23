#pragma once

#include "gdbserver.h"

namespace gdb {

class X86Target : public Target {
public:
	X86Target();
	virtual int rd_reg(int reg_no);
	virtual int wr_reg(int reg_no, addr_type value);
	virtual int rd_mem(addr_type addr);
	virtual int wr_mem(addr_type addr, char data);
	virtual int set_breakpoint(addr_type addr, size_type size = 1);
	virtual int del_breakpoint(addr_type addr, size_type size = 1);
	virtual bool has_breakpoint(addr_type addr, size_type size = 1);
	virtual const std::string& xml_core(void);
	virtual int query(const std::string& type);

protected:

	CONTEXT		_ctx;
};

} // namespace gdb {

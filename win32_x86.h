#pragma once

#include "gdbserver.h"

namespace gdb {

	class X86Target : public Target {
public:
	virtual void rd_reg(int reg_no);
	virtual void wr_reg(int reg_no, unsigned long long value);
	virtual void rd_mem(addr_type addr);
	virtual bool wr_mem(addr_type addr, char data);
	virtual void set_breakpoint(addr_type addr, size_type size = 1);
	virtual void del_breakpoint(addr_type addr, size_type size = 1);
	virtual bool has_breakpoint(addr_type addr, size_type size = 1);
	virtual const std::string& xml_core(void) { static std::string nullstr;  return nullstr; }
};

} // namespace gdb {

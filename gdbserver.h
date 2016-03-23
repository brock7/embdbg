#ifndef __GDBSERVER_HH__
#define __GDBSERVER_HH__

#include <sstream>
#include <cstring> /* strerror */
#include <set>

#include <memory>
#include <vector>
#include <sys/types.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdint.h>
#include <errno.h>
#include <io.h>

typedef LONG_PTR ssize_t;

#define THROW(msg) do {                                          \
    std::stringstream s;                                         \
    s << "Error:" << __FILE__ << ":" << __LINE__ << ": " << msg; \
    throw exception(s.str());                                    \
} while(0)

#define EXPECT(c, m) do {               \
    if (!(c))                           \
        THROW(m);                       \
} while (0)

#define EXPECT_ERRNO(c) do {            \
    if (!(c))                           \
        THROW(std::strerror(errno));    \
} while (0)


namespace gdb {

typedef ULONG_PTR addr_type;
typedef ULONG_PTR addr_diff_type;

class exception : public std::exception {
public:
	exception(std::string msg)
		: msg(msg) { }

	~exception() throw()
	{ }

	virtual const char *what() const throw()
	{
		return msg.c_str();
	}

private:
	std::string msg;
};

class Target {
	friend class Server;
public:
	typedef size_t size_type;

	Target(int num_regs)
		: num_regs(num_regs) { }

	/** */
	virtual void rd_reg(int reg_no) = 0;
	/** */
	virtual void wr_reg(int reg_no, addr_type value) = 0;
	/** */
	virtual void rd_mem(addr_type addr) = 0;
	/** */
	virtual bool wr_mem(addr_type addr, char data) = 0;
	/** */
	virtual void set_breakpoint(addr_type addr, size_type size = 1) = 0;
	/** */
	virtual void del_breakpoint(addr_type addr, size_type size = 1) = 0;
	/** */
	virtual bool has_breakpoint(addr_type addr, size_type size = 1) = 0;
	/** */
	virtual const std::string& xml_core(void) = 0;

protected:
	void put_reg(uint16_t value);
	void put_reg(uint32_t value);
	void put_reg(uint64_t value);

	void put_mem(char value);

private:
	const std::string& rd_one_reg(int reg_no);
	const std::string& rd_all_regs(void);

	const std::string& rd_mem_size(addr_type addr, size_type size);

	bool wr_mem_size(addr_type addr, size_type size, const char *data);

private:
	std::string reg_str;
	std::string mem_str;

	int num_regs;
};

typedef std::shared_ptr<Target> target_ptr;

class Server {
public:

	Server(target_ptr target, const char *port = "1234");
	~Server(void);

	void update(addr_type next_pc);

private:
	typedef std::string payload_type;
	typedef std::string packet_type;

	enum {
		TARGET_STATE_HALTED = 0,
		TARGET_STATE_RUNNING,
		TARGET_STATE_DETACHED,
	} target_state;

	static const size_t PACKET_SIZE = 1024;

	void wait_for_command(void);

	bool extract_payload(const packet_type &packet, payload_type &payload) const;

	void send_payload(const payload_type &payload, int tries = 1) const;
	void send_packet(const char *buf, size_t buf_size) const;

	void recv_payload(payload_type &payload, int tries = 1) const;
	size_t recv_packet(char *buf, size_t buf_size) const;

	int compute_checksum(const payload_type &payload) const;
	char checksum_lsb_ascii(int checksum) const;
	char checksum_msb_ascii(int checksum) const;

	void send_ack(void) const;
	void send_nak(void) const;

	bool got_ack(void) const;
	bool got_nak(void) const;

	void send_ok(void) const;
	void send_empty(void) const;
	void send_error(int error) const;
	void send_trapped(void) const;

private:
	target_ptr		_target;

	int socket_fd;
};

} /* namespace gdb */

#endif /* __GDBSERVER_HH__ */

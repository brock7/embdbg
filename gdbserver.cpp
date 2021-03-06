#include <iostream>
#include <sys/types.h>
#include <assert.h>

#include "gdbserver.h"

class PayloadTokenizer {
public:
	PayloadTokenizer(const std::string& str, const char *sep_)
	{
		char* cstr = (char *)str.c_str();
		char* p = strtok((char*)cstr, sep_);
		while (p) {
			tok.push_back(p);
			p = strtok(NULL, sep_);
		}

		// free(cstr);
	}

	size_t size(void) const
	{
		return tok.size();
	}

	std::string operator[](int idx) const
	{
		return tok[idx];
	}
private:
	std::vector<std::string> tok;
};

/*
 * Helper functions
 */
static char int_to_hex(int value)
{
	assert(0 <= value && value < 16);
	return value < 10 ? value + '0' : value + 'a' - 10;
}

static std::string bin_to_hex(const char *bin, size_t bin_size)
{
	std::string hex;
	for (size_t i = 0; i < bin_size; i++) {
		char c = bin[i];
		hex.push_back(int_to_hex(c >> 4 & 0xf));
		hex.push_back(int_to_hex(c >> 0 & 0xf));
	}
	return hex;
}

static unsigned long str_to_int(const std::string &str, int base = 16)
{
	/* TODO Handle different endianess */
	// reverse byte order only
	return ntohl(strtol(str.c_str(), NULL, base));
}

static ULONG_PTR str_to_addr(const std::string &str, int base = 16)
{
	/* TODO Handle different endianess */
	// reverse byte order only
	return (ULONG_PTR )ntohll((ULONG_PTR)strtoull(str.c_str(), NULL, base));
}

namespace gdb {

void Target::put_reg(uint16_t value)
{
	_reg_str += bin_to_hex((char *)&value, sizeof(value));
}

void Target::put_reg(uint32_t value)
{
	_reg_str += bin_to_hex((char *)&value, sizeof(value));
}

void Target::put_reg(uint64_t value)
{
	_reg_str += bin_to_hex((char *)&value, sizeof(value));
}

void Target::put_reg(ULONG_PTR value)
{
	_reg_str += bin_to_hex((char *)&value, sizeof(value));
}

void Target::put_mem(char value)
{
	_mem_str += int_to_hex(value >> 4 & 0xf);
	_mem_str += int_to_hex(value >> 0 & 0xf);
}

const std::string& Target::rd_one_reg(int reg_no)
{
	_reg_str.clear();
	rd_reg(reg_no);
	return _reg_str;
}

const std::string& Target::rd_all_regs(void)
{
	_reg_str.clear();
	for (int i = 0; i < _num_regs; i++)
		rd_reg(i);
	return _reg_str;
}

const std::string& Target::rd_mem_size(addr_type addr, size_type size)
{
	_mem_str.clear();
	for (size_type i = 0; i < size; i++)
		rd_mem(addr + i);
	return _mem_str;
}

bool Target::wr_mem_size(addr_type addr, size_type size, const char *data)
{
	bool success = true;
	for (size_type i = 0; i < size; i++)
		success = success && wr_mem(addr + i, data[i]) == 0;
	return success;
}

void Target::put_query_info(const std::string& str)
{
	_query_str += str;
}


/* TODO: This constructor does not properly cleanup after itslef in the case
	* of an error and is not exception safe. Fix this. It does however report
	* all errors.
	*/
Server::Server(target_ptr target, const char *port)
	: _target(target), target_state(TARGET_STATE_HALTED)
{
	_extented = false;

	//////////////////////////////////////////////////////////////////////////

	int rc, fd;
	struct sockaddr_in addr;
	socklen_t addr_len;

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(atoi(port));

	fd = socket(AF_INET, SOCK_STREAM, 0);
	EXPECT_ERRNO(fd != -1);

	int optval = 1;
	setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (const char*)&optval, sizeof(optval));

	rc = bind(fd, (sockaddr*)&addr, sizeof(addr));
	EXPECT_ERRNO(rc != -1);

	rc = listen(fd, 1);
	EXPECT_ERRNO(rc != -1);

	addr_len = sizeof(struct sockaddr_in);
	_socket_fd = accept(fd, (struct sockaddr *)&addr, &addr_len);
	EXPECT_ERRNO(_socket_fd != -1);
	closesocket(fd);

	std::cout << "GDB: Accepted connection from "
		<< inet_ntoa(addr.sin_addr) << std::endl;

	send_ack();
	EXPECT(got_ack(), "Failed to establish connection with client");
}

Server::~Server(void)
{
	closesocket(_socket_fd);
}

void Server::send_payload(const payload_type &payload, int tries) const
{
	std::string packet;

	/* Build packet */
	packet.push_back('$');
	do {
		payload_type::const_iterator i = payload.begin();
		payload_type::const_iterator e = payload.end();
		for (; i != e; i++) {
			char c = *i;

			/* Escape '$', '#' and '}' */
			switch (c) {
			case '$':
			case '#':
			case '}':
				packet.push_back('}');
				packet.push_back(c ^ 0x20);
				break;
			}

			packet.push_back(c);
		}
	} while (0);
	packet.push_back('#');

	int c = compute_checksum(payload);
	packet.push_back(checksum_msb_ascii(c));
	packet.push_back(checksum_lsb_ascii(c));

	do {
		send_packet(packet.data(), packet.size());
		if (got_ack())
			break;
	} while (--tries);

	if (!tries)
		THROW("Failed to send packet.");
}

void Server::send_packet(const char *buf, size_t buf_size) const
{
	printf("%s(): '%s'\n", __FUNCTION__, buf);
	const char *p = buf;
	size_t s = buf_size;

	while (s > 0) {
		ssize_t n = send(_socket_fd, p, s, 0);
		EXPECT_ERRNO(n != -1);
		p += n;
		s -= n;
	}
}

void Server::recv_payload(payload_type &payload, int tries) const
{
	packet_type packet;

	do {
		char p[PACKET_SIZE + 1];
		ssize_t size;

		size = recv_packet(p, PACKET_SIZE);
		EXPECT_ERRNO(size != -1);
		p[size] = '\0';

		assert(packet.empty());
		packet = p;

		if (extract_payload(packet, payload))
			break;
		send_nak();
	} while (--tries);

	if (!tries)
		THROW("Failed to receive valid packet.");
	send_ack();
}

size_t Server::recv_packet(char *buf, size_t buf_size) const
{
	ssize_t size;
	size = recv(_socket_fd, buf, buf_size, 0);
	EXPECT_ERRNO(size != -1);
	return size;
}

bool Server::extract_payload(const packet_type &packet, payload_type &payload) const
{
	std::string::const_iterator i = packet.begin();
	std::string::const_iterator e = packet.end();

	/* Packet must begin with a '$' */
	if (i == e || *(i++) != '$')
		return false;

	for (; i != e && *i != '#'; i++){
		char c = *i;

		/* Handle escaped characters */
		if (c == '}') {
			c = *(++i) ^ 0x20;
		}
		payload.push_back(c);
	}

	/* Payload must be followed by a '#' */
	if (i == e || *(i++) != '#')
		return false;

	/* Extract and verify checksum */
	if (i == e)
		return false;
	char checksum_msb = *(i++);

	if (i == e)
		return false;
	char checksum_lsb = *(i++);

	/* TODO Verify checksum */
	return true;
}

int Server::compute_checksum(const payload_type &payload) const
{
	int checksum = 0;
	payload_type::const_iterator i = payload.begin();
	payload_type::const_iterator e = payload.end();
	for (; i != e; i++)
		checksum += *i;
	return checksum % 256;
}

char Server::checksum_lsb_ascii(int csum) const
{
	return int_to_hex(csum >> 0 & 0xf);
}

char Server::checksum_msb_ascii(int csum) const
{
	return int_to_hex(csum >> 4 & 0xf);
}

void Server::send_ack(void) const
{
	send_packet("+", 1);
}

void Server::send_nak(void) const
{
	send_packet("-", 1);
}

bool Server::got_ack(void) const
{
	char buf;
	recv_packet(&buf, 1);
	return buf == '+';
}

bool Server::got_nak(void) const
{
	char buf;
	recv_packet(&buf, 1);
	return buf == '-';
}

void Server::send_ok(void) const
{
	send_payload("OK");
}

void Server::send_empty(void) const
{
	send_payload("");
}

void Server::send_trapped(void) const
{
	send_payload("S05");
}

void Server::send_error(int error) const
{
	std::stringstream ss;
	ss << "E" << error;
	send_payload(ss.str());
}

void Server::wait_for_command(void)
{
	do {
		payload_type payload;
		recv_payload(payload);

		std::cout << "wait_for_comman: payload: " << payload << std::endl;

		switch (payload[0]) {
		case 'D':
			target_state = TARGET_STATE_DETACHED;
			send_ok();
			break;

		case 'g':
			send_payload(_target->rd_all_regs());
			break;

		case 'H':
			if (payload.substr(1, 1) == "g") {
				send_ok();

			}
			else if (payload.substr(1, 1) == "c") {
				send_ok();

			}
			else {
				THROW("Unsupported 'H' command");
			}
			break;

		case 'm':
			do {
				PayloadTokenizer tok(payload.substr(1), ",:");
				EXPECT(tok.size() == 2, "Packet format error. Command m.");

				addr_type addr = str_to_addr(tok[0]);
				addr_type size = str_to_addr(tok[1]);
				send_payload(_target->rd_mem_size(addr, size));
			} while (0);
			break;

		case 'M':
			do {
				PayloadTokenizer tok(payload.substr(1), ",:");
				EXPECT(tok.size() == 2, "Packet format error. Command M.");

				addr_type addr = str_to_addr(tok[0]);
				addr_type size = str_to_addr(tok[1]);
				uint64_t data = str_to_addr(tok[2]);
				if (_target->wr_mem_size(addr, size, (const char *)&data) != 0)
					send_ok();
				else
					send_error(14);
			} while (0);
			break;

		case 'p':
			do {
				PayloadTokenizer tok(payload.substr(1), "=");
				EXPECT(tok.size() == 1, "Packet format error. Command p.");
				send_payload(_target->rd_one_reg(str_to_int(tok[0])));
			} while (0);
			break;

		case 'P':
			do {
				PayloadTokenizer tok(payload.substr(1), "=");
				EXPECT(tok.size() == 2, "Packet format error. Command P.");
				_target->wr_reg(str_to_int(tok[0]), str_to_int(tok[1]));
				send_ok();
			} while (0);
			break;

		case 'q':
			if (_target->query(std::string(payload.begin() + 1, payload.end()))) {

				if (payload.substr(1, 9) == "Supported") {
					send_payload("PacketSize=1024;qXfer:features:read+");

				}
				else if (payload.substr(1, 7) == "Offsets") {
					send_payload("Text=0;Data=0;Bss=0");

				}
				else if (payload.substr(1, 8) == "Attached") {
					send_empty();

				}
				else if (payload.substr(1, 1) == "C") {
					send_payload("QC1");

				}
				else if (payload.substr(1, 8) == "Symbol::") {
					send_ok();

				}
				else if (payload.substr(1, 8) == "TStatus") {
					send_empty();

				}
				else if (payload.substr(1, 29) == "Xfer:features:read:target.xml") {
					send_payload("l" + _target->xml_core());
				}
				else if (payload.substr(1, 11) == "fThreadInfo") {
					// TODO: query thread info
					send_empty();
				}
				else {
					THROW("Unsupported 'q' command");
				}
			}
			break;

		case 'T':
			// TODO: 
			// Find out if the thread thread-id is alive.
			send_empty();
			break;

		case 'v':
			if (payload.substr(1, 5) == "Cont?") {
				send_payload("vCont;s;S;c;C");

			}
			else if (payload.substr(1, 6) == "Cont;c") {
				target_state = TARGET_STATE_RUNNING;

			}
			else {
				THROW("Unsupported 'v' command");
			}
			break;

		case 'z':
		case 'Z':
			if (payload.substr(1, 1) == "0") {
				PayloadTokenizer tok(payload.substr(2), ",");
				EXPECT(tok.size() == 2, "Packet format error (Z0)");

				addr_type addr = str_to_int(tok[0]);
				size_t size = str_to_int(tok[1]);

				if (payload[0] == 'z')
					_target->del_breakpoint(addr, size);
				else
					_target->set_breakpoint(addr, size);

				send_ok();
			}
			else {
				THROW("Unsupported 'z' command");
			}
			break;

		case 'X':
			/* We do not support binary data transfers */
			send_empty();
			break;

		case '?':
			/* We are always stopped by a SIGTRAP */
			send_trapped();
			break;

		case '!':
			//  extended mode
			send_empty();
			break;

		default:
			THROW("Unsupported command");
			break;
		}
	} while (target_state == TARGET_STATE_HALTED);
}

void Server::update(addr_type next_pc)
{
	switch (target_state) {
	case TARGET_STATE_HALTED:
		wait_for_command();
		break;

	case TARGET_STATE_RUNNING:
		if (_target->has_breakpoint(next_pc)) {
			target_state = TARGET_STATE_HALTED;
			send_trapped(); /* Let the client know that we stopped */

			wait_for_command();
		}
		break;

	case TARGET_STATE_DETACHED:
		/* Do nothing */
		break;

	default:
		assert(0);
	}
}

} /* namespace gdb */

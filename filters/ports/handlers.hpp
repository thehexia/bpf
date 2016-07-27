#ifndef HANDLERS_HPP
#define HANDLERS_HPP

#include <pcap/pcap.h>

// Module will contain packet receive handlers for pcap_loop.


namespace bpf_test
{

void blocked_port_logger(u_char*, pcap_pkthdr const*, u_char const*);
void allowed_port_logger(u_char*, pcap_pkthdr const*, u_char const*);

} // namespace bpf_test

#endif

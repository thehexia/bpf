#ifndef PCAP_UTIL_HPP
#define PCAP_UTIL_HPP

#include "freeflow/capture.hpp"

namespace bpf_test
{

// Compiles BPF filter from syntax provided in file.
inline int
compile_bpf(ff::cap::Stream& stream, bpf_program& prog, char const* filter, int netmask)
{
  return pcap_compile(stream.handle(), &prog, filter, 1, netmask);
}

// Sets filter on handle.
inline void
set_filter(ff::cap::Stream& stream, bpf_program& prog, char const* filter)
{
  if (pcap_setfilter(stream.handle(), &prog) == -1) {
		fprintf(stderr, "cannot set pcap filter %s: %s\n", filter, stream.error());
		exit(1);
	}
}


// Starts a pcap loop with a given callback function.
inline void
pcap_loop(ff::cap::Stream& stream, pcap_handler callback, int iterations, u_char* user_data = nullptr)
{
  // if (pcap_loop(stream.handle(), -1, callback, user_data) < 0) {
	// 	fprintf(stderr, "cannot get raw packet: %s\n", pcap_geterr(stream.handle()));
	// 	exit(1);
	// }
  ff::cap::Packet p;
  while (stream.get(p)) {
    for (int i = 0; i < iterations; ++i) {
      callback(user_data, p.hdr, p.data());
    }
  }
}


} // namespace bpf_test

#endif

#ifndef PCAP_UTIL_HPP
#define PCAP_UTIL_HPP

#include "freeflow/capture.hpp"
#include <iomanip>
#include <cassert>
#include <cstring>

namespace bpf_test
{

// Compiles BPF filter from syntax provided in file.
inline int
compile_bpf(ff::cap::Stream& stream, bpf_program& prog, char const* filter, int netmask)
{
  return pcap_compile(stream.handle(), &prog, filter, 0, netmask);
}


// Sets filter on handle.
// NOTE: Using this will apply the filter in the kernel if the OS supports it.
// On Linux and BSD variants, there will almost certainly be kernel level filtering support.
inline void
set_filter(ff::cap::Stream& stream, bpf_program prog, char const* filter)
{
  if (pcap_setfilter(stream.handle(), &prog) == -1) {
		fprintf(stderr, "cannot set pcap filter %s: %s\n", filter, stream.error());
		exit(1);
	}
}


// Print filter instructions.
inline void
print_filter_instructions(bpf_program p) {
  std::cout << "Instructions: " << p.bf_len << '\n';
  for (unsigned int i = 0; i < p.bf_len; ++i) {
    std::cout << std::setw(5) << p.bf_insns->code << '\n';
    ++p.bf_insns; // Increment program counter.
  }
}


// Starts a pcap loop with a given callback function.
inline void
filter_loop(ff::cap::Stream& stream, pcap_handler callback, int iterations, u_char* user_data = nullptr)
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


// Manual BPF filtering in userspace using raw filtering interface.
// Returns number of packets filtered.
inline int
user_filter_loop(ff::cap::Stream& stream, bpf_program prog,
                 pcap_handler allow_callback, pcap_handler block_callback,
                 int iterations, u_char* user_data = nullptr)
{
  // Statistics
  int pktno = 0;

  ff::cap::Packet p;
  while (stream.get(p)) {
    assert(p.data());
    assert(prog.bf_insns);

    for (int i = 0; i < iterations; ++i) {
      ++pktno;

////////////////////////////////////////////
/// This copy isn't strictly necessary
/// because BPF doesn't modify packet data
/// and therefore doesn't need a mutable buffer.
/// However, because the Steve runtime has to
/// perform this copy, we perform it here so
/// as to be consistent.
////////////////////////////////////////////
      unsigned char buf[2048];
      if (p.captured_size() <= 2048)
        std::memcpy(&buf[0], p.data(), p.captured_size());
      else
        continue;
////////////////////////////////////////////

      if (bpf_filter(prog.bf_insns, p.data(), p.total_size(), p.captured_size()))
        allow_callback(user_data, p.hdr, buf);
      else if (block_callback)
        block_callback(user_data, p.hdr, buf);
    }
  }

  return pktno;
}


} // namespace bpf_test

#endif

#include <pcap/pcap.h>
#include <pcap/bpf.h>

#include "file.hpp"
#include "pcap_utility.hpp"
#include "timer.hpp"
#include "handlers.hpp"

#include <cstdlib>
#include <ctime>
#include <stdexcept>
#include <string>
#include <cstring>
#include <memory>
#include <iostream>
#include <fstream>

using namespace ff;
using namespace bpf_test;

int
main(int argc, char* argv[])
{
  // Read the file containing filter instructions.
  if (argc < 2)
    throw std::runtime_error("Usage: driver <bpf-program> <pcap-file> <output-file> [ <iterations> ]");
  bpf_test::File bpf(argv[1]);

  // Load the given pcap file.
  if (argc < 3)
    throw std::runtime_error("Usage: driver <bpf-program> <pcap-file> <output-file> [ <iterations> ]");
  char* pcap_file = argv[2];

  // Get the dump output file.
  if (argc < 4)
    throw std::runtime_error("Usage: driver <bpf-program> <pcap-file> <output-file> [ <iterations> ]");
  char* dump_file = argv[3];

  // Check for number of copies/iterations. Default 1.
  int iterations = 1;
  if (argc > 4)
    iterations = std::stoi(argv[4]);
  std::cout << "Iterations: " << iterations << '\n';

  std::cout << "Loading: " << pcap_file << '\n';
  // Open an offline stream capture.
  cap::Stream cap(cap::offline(pcap_file));
  if (cap.link_type() != cap::ethernet_link) {
    std::cerr << "error: input is not ethernet\n";
    return 1;
  }

  // Set up the filter.
  bpf_program prog;
  std::string filter = bpf.read();
  unsigned int dl_len = ff::cap::linktype_len(cap.link_type());
  compile_bpf(cap, prog, filter.c_str(), PCAP_NETMASK_UNKNOWN);


  cap::Dump_stream dump(dump_file);
  std::cout << "Starting filter\n";

  Timer t;
  int pktno = user_filter_loop(cap, prog, pcap_dump, nullptr,
                               iterations, (u_char*) dump.dumper());
  std::cout << "Pps: " << pktno / t.elapsed() << '\n';
}

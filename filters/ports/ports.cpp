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
    throw std::runtime_error("No pcap or filter file given.");
  bpf_test::File bpf(argv[1]);

  // Load the given pcap file.
  if (argc < 3)
    throw std::runtime_error("No pcap or filter file given.");
  char* pcap_file = argv[2];

  // Check for number of copies/iterations. Default 1.
  int iterations = 1;
  if (argc > 2)
    iterations = std::stoi(argv[3]);
  std::cout << "Iterations: " << iterations << '\n';

  std::cout << "Loading: " << pcap_file << '\n';
  // Open an offline stream capture.
  cap::Stream cap(cap::offline(pcap_file));
  if (cap.link_type() != cap::ethernet_link) {
    std::cerr << "error: input is not ethernet\n";
    return 1;
  }

  // Set up the filter.
  unsigned int dl_len = cap::linktype_len(cap.link_type());
  bpf_program prog;
  std::string filter = bpf.read();
  compile_bpf(cap, prog, filter.c_str(), PCAP_NETMASK_UNKNOWN);
  set_filter(cap, prog, filter.c_str());
  std::cout << "Set filter: " << filter << '\n';

  // Start looping and filtering packets.
  std::cout << "Starting filter\n";
  {
    Timer t;
    pcap_loop(cap, allowed_port_logger, iterations, (u_char*) &dl_len);
  }

  // while (cap.get(p)) {
  //   for (int i = 0; i < iterations; i++) {
  //     std::uint8_t* buf = new std::uint8_t[p.captured_size()];
  //     std::unique_ptr<uint8_t> ptr(buf);
  //     std::memcpy(&buf[0], p.data(), p.captured_size());
  //   }
  // }
}

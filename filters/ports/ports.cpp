#include <pcap/pcap.h>
#include <pcap/bpf.h>

#include "freeflow/capture.hpp"
#include "file.hpp"

#include <cstdlib>
#include <ctime>
#include <stdexcept>
#include <string>
#include <cstring>
#include <memory>
#include <iostream>
#include <fstream>

using namespace ff;

bool compile_bpf(pcap_t* handle, bpf_program prog, char const* filter);

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
  if (argc > 4)
    iterations = std::stoi(argv[3]);

  std::cout << "Loading: " << pcap_file << std::endl;
  // Open an offline stream capture.
  cap::Stream cap(cap::offline(pcap_file));
  if (cap.link_type() != cap::ethernet_link) {
    std::cerr << "error: input is not ethernet\n";
    return 1;
  }

  // Start reading in the capture.
  pcap_t* pcap_handle = cap.handle();

  // while (cap.get(p)) {
  //   for (int i = 0; i < iterations; i++) {
  //     std::uint8_t* buf = new std::uint8_t[p.captured_size()];
  //     std::unique_ptr<uint8_t> ptr(buf);
  //     std::memcpy(&buf[0], p.data(), p.captured_size());
  //   }
  // }
}


// Compiles BPF filter from syntax provided in file.
bool
compile_bpf(pcap_t* handle, bpf_program prog, char const* filter)
{

}

add_executable(ports ports.cpp handlers.cpp)

target_link_libraries(ports pcap)

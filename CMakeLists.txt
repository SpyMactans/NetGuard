cmake_minimum_required(VERSION 3.10)
project(netguard CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

add_compile_options(-Wall -Wextra -O2)

find_package(Threads REQUIRED)
find_package(PkgConfig REQUIRED)
pkg_check_modules(PCAP REQUIRED libpcap)

include_directories(include)

add_executable(netguard
    src/main.cpp
    src/arp_scan.cpp
    src/port_scan.cpp
    src/wifi_scan.cpp
    src/baseline.cpp
    src/alert.cpp
    src/dashboard.cpp
    src/oui_lookup.cpp
    src/util.cpp
)

target_include_directories(netguard PRIVATE ${PCAP_INCLUDE_DIRS})
target_link_libraries(netguard
    PRIVATE
    Threads::Threads
    ncurses
    ${PCAP_LIBRARIES}
)
target_link_directories(netguard PRIVATE ${PCAP_LIBRARY_DIRS})

install(TARGETS netguard DESTINATION bin)

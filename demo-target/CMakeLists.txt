#
# SmartLock-7A21 - deliberately vulnerable BLE demo target
#
cmake_minimum_required(VERSION 3.20.0)

find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(demo_target)

target_sources(app PRIVATE
  src/main.c
  src/frame.c
)
target_include_directories(app PRIVATE src)

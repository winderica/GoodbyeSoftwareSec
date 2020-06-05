cmake_minimum_required(VERSION 3.17)

project(4)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} ${CMAKE_CURRENT_SOURCE_DIR})

find_package(BOTAN REQUIRED)
find_package(pe-parse REQUIRED PATHS ${CMAKE_CURRENT_SOURCE_DIR}/lib/pe-parse/build)

include_directories(SYSTEM ${BOTAN_INCLUDE_DIRS})
add_executable(miniAntiVirus miniAntiVirus.cpp)
target_link_libraries(miniAntiVirus ${BOTAN_LIBRARIES})
target_link_libraries(miniAntiVirus pe-parse::pe-parser-library)

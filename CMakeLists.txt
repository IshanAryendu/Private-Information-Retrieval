# cmake_minimum_required(VERSION 3.10)
# project(pir_implementations)

# # Set C++ standard
# set(CMAKE_CXX_STANDARD 17)
# set(CMAKE_CXX_STANDARD_REQUIRED ON)

# # Find OpenSSL package
# find_package(OpenSSL REQUIRED)

# # Find SEAL package (use the installed version 4.1)
# find_package(SEAL 4.1 REQUIRED)

# # Add the executables
# add_executable(garbled_circuit_pir garbled_circuit_pir.cpp)
# add_executable(homomorphic_pir homomorphic_pir.cpp)

# # Link against OpenSSL libraries for garbled circuit implementation
# target_link_libraries(garbled_circuit_pir OpenSSL::SSL OpenSSL::Crypto)

# # Link against SEAL for homomorphic encryption implementation
# target_link_libraries(homomorphic_pir SEAL::seal)

# # Add compiler flags
# if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
#     target_compile_options(garbled_circuit_pir PRIVATE -O3 -Wall -Wextra)
#     target_compile_options(homomorphic_pir PRIVATE -O3 -Wall -Wextra)
# endif()

# # Enable testing
# enable_testing()

# # Add test for garbled circuit PIR
# add_test(NAME GarbledCircuitPIRTest 
#          COMMAND garbled_circuit_pir --test)

# # Add test for homomorphic PIR
# add_test(NAME HomomorphicPIRTest 
#          COMMAND homomorphic_pir --test)

# # Add benchmark target
# add_custom_target(benchmark
#     COMMAND garbled_circuit_pir --benchmark
#     COMMAND homomorphic_pir --benchmark
#     COMMENT "Running benchmarks for PIR implementations"
# )

# # Add documentation target
# find_package(Doxygen QUIET)
# if(DOXYGEN_FOUND)
#     add_custom_target(docs
#         ${DOXYGEN_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/Doxyfile
#         WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
#         COMMENT "Generating API documentation with Doxygen"
#         VERBATIM
#     )
# endif()

cmake_minimum_required(VERSION 3.10)
project(pir_implementations)

# Set C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Find OpenSSL package
find_package(OpenSSL REQUIRED)

# Find SEAL package (use the installed version 4.1)
find_package(SEAL 4.1 REQUIRED)

# Add the executables
add_executable(garbled_circuit_pir garbled_circuit_pir.cpp)
add_executable(homomorphic_pir homomorphic_pir.cpp)

# Link against OpenSSL libraries for garbled circuit implementation
target_link_libraries(garbled_circuit_pir OpenSSL::SSL OpenSSL::Crypto)

# Link against SEAL for homomorphic encryption implementation
target_link_libraries(homomorphic_pir SEAL::seal)

# Add compiler flags
if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(garbled_circuit_pir PRIVATE -O3)
    target_compile_options(homomorphic_pir PRIVATE -O3)
endif()



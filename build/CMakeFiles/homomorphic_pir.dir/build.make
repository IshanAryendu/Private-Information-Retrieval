# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.28

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:

#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:

# Disable VCS-based implicit rules.
% : %,v

# Disable VCS-based implicit rules.
% : RCS/%

# Disable VCS-based implicit rules.
% : RCS/%,v

# Disable VCS-based implicit rules.
% : SCCS/s.%

# Disable VCS-based implicit rules.
% : s.%

.SUFFIXES: .hpux_make_needs_suffix_list

# Command-line flag to silence nested $(MAKE).
$(VERBOSE)MAKESILENT = -s

#Suppress display of executed commands.
$(VERBOSE).SILENT:

# A target that is always out of date.
cmake_force:
.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /usr/bin/cmake

# The command to remove a file.
RM = /usr/bin/cmake -E rm -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /home/ishan/Desktop/seal_test

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/ishan/Desktop/seal_test/build

# Include any dependencies generated for this target.
include CMakeFiles/homomorphic_pir.dir/depend.make
# Include any dependencies generated by the compiler for this target.
include CMakeFiles/homomorphic_pir.dir/compiler_depend.make

# Include the progress variables for this target.
include CMakeFiles/homomorphic_pir.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/homomorphic_pir.dir/flags.make

CMakeFiles/homomorphic_pir.dir/homomorphic_pir.cpp.o: CMakeFiles/homomorphic_pir.dir/flags.make
CMakeFiles/homomorphic_pir.dir/homomorphic_pir.cpp.o: /home/ishan/Desktop/seal_test/homomorphic_pir.cpp
CMakeFiles/homomorphic_pir.dir/homomorphic_pir.cpp.o: CMakeFiles/homomorphic_pir.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green --progress-dir=/home/ishan/Desktop/seal_test/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object CMakeFiles/homomorphic_pir.dir/homomorphic_pir.cpp.o"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -MD -MT CMakeFiles/homomorphic_pir.dir/homomorphic_pir.cpp.o -MF CMakeFiles/homomorphic_pir.dir/homomorphic_pir.cpp.o.d -o CMakeFiles/homomorphic_pir.dir/homomorphic_pir.cpp.o -c /home/ishan/Desktop/seal_test/homomorphic_pir.cpp

CMakeFiles/homomorphic_pir.dir/homomorphic_pir.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green "Preprocessing CXX source to CMakeFiles/homomorphic_pir.dir/homomorphic_pir.cpp.i"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/ishan/Desktop/seal_test/homomorphic_pir.cpp > CMakeFiles/homomorphic_pir.dir/homomorphic_pir.cpp.i

CMakeFiles/homomorphic_pir.dir/homomorphic_pir.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green "Compiling CXX source to assembly CMakeFiles/homomorphic_pir.dir/homomorphic_pir.cpp.s"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/ishan/Desktop/seal_test/homomorphic_pir.cpp -o CMakeFiles/homomorphic_pir.dir/homomorphic_pir.cpp.s

# Object files for target homomorphic_pir
homomorphic_pir_OBJECTS = \
"CMakeFiles/homomorphic_pir.dir/homomorphic_pir.cpp.o"

# External object files for target homomorphic_pir
homomorphic_pir_EXTERNAL_OBJECTS =

homomorphic_pir: CMakeFiles/homomorphic_pir.dir/homomorphic_pir.cpp.o
homomorphic_pir: CMakeFiles/homomorphic_pir.dir/build.make
homomorphic_pir: /usr/local/lib/libseal-4.1.a
homomorphic_pir: CMakeFiles/homomorphic_pir.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green --bold --progress-dir=/home/ishan/Desktop/seal_test/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking CXX executable homomorphic_pir"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/homomorphic_pir.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/homomorphic_pir.dir/build: homomorphic_pir
.PHONY : CMakeFiles/homomorphic_pir.dir/build

CMakeFiles/homomorphic_pir.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/homomorphic_pir.dir/cmake_clean.cmake
.PHONY : CMakeFiles/homomorphic_pir.dir/clean

CMakeFiles/homomorphic_pir.dir/depend:
	cd /home/ishan/Desktop/seal_test/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/ishan/Desktop/seal_test /home/ishan/Desktop/seal_test /home/ishan/Desktop/seal_test/build /home/ishan/Desktop/seal_test/build /home/ishan/Desktop/seal_test/build/CMakeFiles/homomorphic_pir.dir/DependInfo.cmake "--color=$(COLOR)"
.PHONY : CMakeFiles/homomorphic_pir.dir/depend


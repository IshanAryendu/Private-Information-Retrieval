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
include CMakeFiles/seal_test.dir/depend.make
# Include any dependencies generated by the compiler for this target.
include CMakeFiles/seal_test.dir/compiler_depend.make

# Include the progress variables for this target.
include CMakeFiles/seal_test.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/seal_test.dir/flags.make

CMakeFiles/seal_test.dir/seal_test.cpp.o: CMakeFiles/seal_test.dir/flags.make
CMakeFiles/seal_test.dir/seal_test.cpp.o: /home/ishan/Desktop/seal_test/seal_test.cpp
CMakeFiles/seal_test.dir/seal_test.cpp.o: CMakeFiles/seal_test.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green --progress-dir=/home/ishan/Desktop/seal_test/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object CMakeFiles/seal_test.dir/seal_test.cpp.o"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -MD -MT CMakeFiles/seal_test.dir/seal_test.cpp.o -MF CMakeFiles/seal_test.dir/seal_test.cpp.o.d -o CMakeFiles/seal_test.dir/seal_test.cpp.o -c /home/ishan/Desktop/seal_test/seal_test.cpp

CMakeFiles/seal_test.dir/seal_test.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green "Preprocessing CXX source to CMakeFiles/seal_test.dir/seal_test.cpp.i"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/ishan/Desktop/seal_test/seal_test.cpp > CMakeFiles/seal_test.dir/seal_test.cpp.i

CMakeFiles/seal_test.dir/seal_test.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green "Compiling CXX source to assembly CMakeFiles/seal_test.dir/seal_test.cpp.s"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/ishan/Desktop/seal_test/seal_test.cpp -o CMakeFiles/seal_test.dir/seal_test.cpp.s

# Object files for target seal_test
seal_test_OBJECTS = \
"CMakeFiles/seal_test.dir/seal_test.cpp.o"

# External object files for target seal_test
seal_test_EXTERNAL_OBJECTS =

seal_test: CMakeFiles/seal_test.dir/seal_test.cpp.o
seal_test: CMakeFiles/seal_test.dir/build.make
seal_test: /usr/local/lib/libseal-4.1.a
seal_test: CMakeFiles/seal_test.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green --bold --progress-dir=/home/ishan/Desktop/seal_test/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking CXX executable seal_test"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/seal_test.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/seal_test.dir/build: seal_test
.PHONY : CMakeFiles/seal_test.dir/build

CMakeFiles/seal_test.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/seal_test.dir/cmake_clean.cmake
.PHONY : CMakeFiles/seal_test.dir/clean

CMakeFiles/seal_test.dir/depend:
	cd /home/ishan/Desktop/seal_test/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/ishan/Desktop/seal_test /home/ishan/Desktop/seal_test /home/ishan/Desktop/seal_test/build /home/ishan/Desktop/seal_test/build /home/ishan/Desktop/seal_test/build/CMakeFiles/seal_test.dir/DependInfo.cmake "--color=$(COLOR)"
.PHONY : CMakeFiles/seal_test.dir/depend


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
CMAKE_SOURCE_DIR = /workspaces/Expense-Tracker-CPP

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /workspaces/Expense-Tracker-CPP/build

# Include any dependencies generated for this target.
include CMakeFiles/expense_tracker.dir/depend.make
# Include any dependencies generated by the compiler for this target.
include CMakeFiles/expense_tracker.dir/compiler_depend.make

# Include the progress variables for this target.
include CMakeFiles/expense_tracker.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/expense_tracker.dir/flags.make

CMakeFiles/expense_tracker.dir/src/database.cpp.o: CMakeFiles/expense_tracker.dir/flags.make
CMakeFiles/expense_tracker.dir/src/database.cpp.o: /workspaces/Expense-Tracker-CPP/src/database.cpp
CMakeFiles/expense_tracker.dir/src/database.cpp.o: CMakeFiles/expense_tracker.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green --progress-dir=/workspaces/Expense-Tracker-CPP/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object CMakeFiles/expense_tracker.dir/src/database.cpp.o"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -MD -MT CMakeFiles/expense_tracker.dir/src/database.cpp.o -MF CMakeFiles/expense_tracker.dir/src/database.cpp.o.d -o CMakeFiles/expense_tracker.dir/src/database.cpp.o -c /workspaces/Expense-Tracker-CPP/src/database.cpp

CMakeFiles/expense_tracker.dir/src/database.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green "Preprocessing CXX source to CMakeFiles/expense_tracker.dir/src/database.cpp.i"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /workspaces/Expense-Tracker-CPP/src/database.cpp > CMakeFiles/expense_tracker.dir/src/database.cpp.i

CMakeFiles/expense_tracker.dir/src/database.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green "Compiling CXX source to assembly CMakeFiles/expense_tracker.dir/src/database.cpp.s"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /workspaces/Expense-Tracker-CPP/src/database.cpp -o CMakeFiles/expense_tracker.dir/src/database.cpp.s

CMakeFiles/expense_tracker.dir/src/main.cpp.o: CMakeFiles/expense_tracker.dir/flags.make
CMakeFiles/expense_tracker.dir/src/main.cpp.o: /workspaces/Expense-Tracker-CPP/src/main.cpp
CMakeFiles/expense_tracker.dir/src/main.cpp.o: CMakeFiles/expense_tracker.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green --progress-dir=/workspaces/Expense-Tracker-CPP/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Building CXX object CMakeFiles/expense_tracker.dir/src/main.cpp.o"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -MD -MT CMakeFiles/expense_tracker.dir/src/main.cpp.o -MF CMakeFiles/expense_tracker.dir/src/main.cpp.o.d -o CMakeFiles/expense_tracker.dir/src/main.cpp.o -c /workspaces/Expense-Tracker-CPP/src/main.cpp

CMakeFiles/expense_tracker.dir/src/main.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green "Preprocessing CXX source to CMakeFiles/expense_tracker.dir/src/main.cpp.i"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /workspaces/Expense-Tracker-CPP/src/main.cpp > CMakeFiles/expense_tracker.dir/src/main.cpp.i

CMakeFiles/expense_tracker.dir/src/main.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green "Compiling CXX source to assembly CMakeFiles/expense_tracker.dir/src/main.cpp.s"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /workspaces/Expense-Tracker-CPP/src/main.cpp -o CMakeFiles/expense_tracker.dir/src/main.cpp.s

CMakeFiles/expense_tracker.dir/src/memory_log.cpp.o: CMakeFiles/expense_tracker.dir/flags.make
CMakeFiles/expense_tracker.dir/src/memory_log.cpp.o: /workspaces/Expense-Tracker-CPP/src/memory_log.cpp
CMakeFiles/expense_tracker.dir/src/memory_log.cpp.o: CMakeFiles/expense_tracker.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green --progress-dir=/workspaces/Expense-Tracker-CPP/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_3) "Building CXX object CMakeFiles/expense_tracker.dir/src/memory_log.cpp.o"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -MD -MT CMakeFiles/expense_tracker.dir/src/memory_log.cpp.o -MF CMakeFiles/expense_tracker.dir/src/memory_log.cpp.o.d -o CMakeFiles/expense_tracker.dir/src/memory_log.cpp.o -c /workspaces/Expense-Tracker-CPP/src/memory_log.cpp

CMakeFiles/expense_tracker.dir/src/memory_log.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green "Preprocessing CXX source to CMakeFiles/expense_tracker.dir/src/memory_log.cpp.i"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /workspaces/Expense-Tracker-CPP/src/memory_log.cpp > CMakeFiles/expense_tracker.dir/src/memory_log.cpp.i

CMakeFiles/expense_tracker.dir/src/memory_log.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green "Compiling CXX source to assembly CMakeFiles/expense_tracker.dir/src/memory_log.cpp.s"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /workspaces/Expense-Tracker-CPP/src/memory_log.cpp -o CMakeFiles/expense_tracker.dir/src/memory_log.cpp.s

# Object files for target expense_tracker
expense_tracker_OBJECTS = \
"CMakeFiles/expense_tracker.dir/src/database.cpp.o" \
"CMakeFiles/expense_tracker.dir/src/main.cpp.o" \
"CMakeFiles/expense_tracker.dir/src/memory_log.cpp.o"

# External object files for target expense_tracker
expense_tracker_EXTERNAL_OBJECTS =

expense_tracker: CMakeFiles/expense_tracker.dir/src/database.cpp.o
expense_tracker: CMakeFiles/expense_tracker.dir/src/main.cpp.o
expense_tracker: CMakeFiles/expense_tracker.dir/src/memory_log.cpp.o
expense_tracker: CMakeFiles/expense_tracker.dir/build.make
expense_tracker: CMakeFiles/expense_tracker.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green --bold --progress-dir=/workspaces/Expense-Tracker-CPP/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_4) "Linking CXX executable expense_tracker"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/expense_tracker.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/expense_tracker.dir/build: expense_tracker
.PHONY : CMakeFiles/expense_tracker.dir/build

CMakeFiles/expense_tracker.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/expense_tracker.dir/cmake_clean.cmake
.PHONY : CMakeFiles/expense_tracker.dir/clean

CMakeFiles/expense_tracker.dir/depend:
	cd /workspaces/Expense-Tracker-CPP/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /workspaces/Expense-Tracker-CPP /workspaces/Expense-Tracker-CPP /workspaces/Expense-Tracker-CPP/build /workspaces/Expense-Tracker-CPP/build /workspaces/Expense-Tracker-CPP/build/CMakeFiles/expense_tracker.dir/DependInfo.cmake "--color=$(COLOR)"
.PHONY : CMakeFiles/expense_tracker.dir/depend


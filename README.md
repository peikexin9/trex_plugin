# Trex Plugin

---

## Installation

---

First, Download the Trex Plugin from Github.

Next, cd to the downloaded folder of Trex Plugin: `cd /path/to/TrexPlugin`

Use gradle to build extension: `GHIDRA_INSTALL_DIR=${GHIDRA_HOME} gradle`

Then, copy the compiled zip file to `${GHIDRA_HOME}/Extensions/Ghidra`, the compiled file can be found under the **dist** folder.

 Finally, install it in Ghidra `File → Install Extensions...`

## Compile C++ Executable File

---

First, cd to the c++ folder in plugin: `cd c++`

Next, configure CMake file by `cmake -DCMAKE_PREFIX_PATH=/path/to/libtorch`

Then, compile c++ source file: `cmake --build . --config Release`

Finally, move the compiled file to ghidra_scripts folder: `mv c++ ../ghidra_scripts`
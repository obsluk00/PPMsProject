# PPMsProject
How this install
- This project is built using CMake & Make
- After cloning the repo, create a "build" in the repo dir
- Within the terminal, run "cmake .." and "make" afterwards. (If you're running on macOS, please modify the C/C++ compiler property in the CMakeLists.txt file.

How to use this codebase

- To test BGV and BFV, please run the main file in the main-branch.
- To test CKKS please run the main file in the float-arithmetic-branch.
- To test DM and/or CGGI, please run the main file in the logic-circus-branch.ch
- Please make sure to create a Results folder within the build dir, and to create a "{xxx}Results" folder within it (with xxx being the FHE scheme to be benchmarked).


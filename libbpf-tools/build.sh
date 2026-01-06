#!/bin/bash

rm -rf build CMakeCache.txt CMakeFiles/

mkdir -p build && cd build && cmake ..

make

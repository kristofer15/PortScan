#!/bin/bash

for filename in ./*.cpp; do
	g++ -std=c++11 -pthread $filename -o ./bin/$(basename $filename .cpp)
done

#!/bin/bash

for filename in ./*.cpp; do
	g++ $filename -o ./bin/$(basename $filename .cpp)
done

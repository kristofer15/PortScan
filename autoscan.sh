#!/bin/bash

for c in $(seq $2 $3);
do
	rm REAL_hosts.txt
	touch REAL_hosts.txt
	for d in $(seq $4 $5);
	do
		echo $1.$c.$d >> REAL_hosts.txt
	done

	sleep 2s # Give the file writer time to complete
	sudo bin/scanner -s
	mkdir -p results/$1.x.x
	mv results.csv results/$1.x.x/$1.$c.x.csv
done



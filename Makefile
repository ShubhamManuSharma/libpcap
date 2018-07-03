#!/bin/bash

run: insert_filter.o 
	gcc -o run insert_filter.o  -lpcap 

insert_filter.o: insert_filter.c headers.h declaration.h 
		gcc -c  insert_filter.c  

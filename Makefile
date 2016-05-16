C = gcc
FLAGS = -Wall -ggdb

all: rst 

rst: rst.c 
	$(C) $(FLAGS) -o rst rst.c -lpcap

clean: 
	rm rst

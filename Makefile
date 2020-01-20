CC=gcc
output=main
files=test.c _malloc.c
debugger=gdb
flags=-g -O0 -lpthread

all:
	$(CC) $(flags) -o $(output) $(files)

run:
	./$(output)

debug:
	$(debugger) ./$(output)
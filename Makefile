CC=gcc
output=main
files=test.c _malloc.c

all:
	$(CC) -g -O0 -o $(output) $(files)

run:
	./$(output)

debug:
	gdb ./$(output)
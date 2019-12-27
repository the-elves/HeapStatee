all: driver.c
	gcc driver.c api.o -o driver.out -g 
driver.c: api.o api.h
api.o: api.c
	gcc api.c -c -g

#CC = /home/illuminati/College/Guided_HML/compile-oldlibc.sh
CC = gcc
all: driver.c
	$(CC) driver.c api.o -o driver.out -g 
driver.c: api.o api.h
api.o: api.c
	$(CC) api.c -c -g

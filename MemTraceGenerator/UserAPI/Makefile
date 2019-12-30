CC = /home/ajinkya/College/Guided_HML/glibc/compile.sh
#CC = gcc
all: driver.c
	$(CC) driver.c api.o -o driver.out -g -no-pie -fno-PIC
driver.c: api.o api.h
api.o: api.c
	$(CC) api.c -c -g -fno-PIC

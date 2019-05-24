#include<stdio.h>
#include<stdlib.h>
int main(){
	void *p, *q, *r;
	p	= malloc(30);
	q = malloc(30);
	r = malloc(30);
	free(q);
	q = malloc(50);
}

#include<stdio.h>
#include<stdlib.h>
int main(){
	void *fn, *ln, *hno, *st, *cs;
	void *p;
	p = malloc(200);
	fn = malloc(110);
	ln = malloc(39);
	hno = malloc(44);
	st = malloc(128);
	cs = malloc(127);

	free(hno);
	free(st);
	free(cs);
	free(ln);
	free(fn);

}

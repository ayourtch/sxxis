sxxis: sxxis.c
	gcc -g -o sxxis -lev -ludns sxxis.c

clean:
	${RM} sxxis


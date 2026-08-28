CFLAGS+=-Wall -Wextra -Wpedantic -Werror -std=gnu11
LDFLAGS+=-lsodium -lb2

OBJS=main.o\
     wg.o

wgtest: ${OBJS}
	${CC} ${CFLAGS} ${LDFLAGS} -o wgtest ${OBJS}

main.o: main.c wg.h
	${CC} ${CFLAGS} -c -o main.o main.c

wg.o: wg.c wg.h
	${CC} ${CFLAGS} -c -o wg.o wg.c

.PHONY: clean
clean:
	rm -f wgtest ${OBJS}

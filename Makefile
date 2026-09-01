CFLAGS+=-Wall -Wextra -Wpedantic -Werror -std=gnu23
LDFLAGS+=-lsodium -lb2

OBJS=main.o\
     utils.o\
     wg.o

wgtest: ${OBJS}
	${CC} ${CFLAGS} ${LDFLAGS} -o wgtest ${OBJS}

main.o: main.c wg.h log.h utils.h
	${CC} ${CFLAGS} -c -o main.o main.c

utils.o: utils.c utils.h log.h
	${CC} ${CFLAGS} -c -o utils.o utils.c

wg.o: wg.c wg.h
	${CC} ${CFLAGS} -c -o wg.o wg.c

.PHONY: clean
clean:
	rm -f wgtest ${OBJS}

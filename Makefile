C_STANDARD=gnu23

CFLAGS+=-Wall -Wextra -Wpedantic -Werror -std=${C_STANDARD}
LDFLAGS+=-lsodium -lb2

OBJS=main.o\
     wg.o\
     utils.o

wgtest: ${OBJS}
	${CC} ${CFLAGS} ${LDFLAGS} -o wgtest ${OBJS}

main.o: main.c wg.h utils.h garbage.h log.h
	${CC} ${CFLAGS} -c -o main.o main.c

wg.o: wg.c wg.h
	${CC} ${CFLAGS} -c -o wg.o wg.c

utils.o: utils.c utils.h log.h
	${CC} ${CFLAGS} -c -o utils.o utils.c

.PHONY: clean
clean:
	rm -f wgtest ${OBJS}

.PHONY: lint
lint:
	clang-tidy --extra-arg=-std=${C_STANDARD} *.c *.h

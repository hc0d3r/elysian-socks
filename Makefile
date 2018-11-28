.PHONY: clean

CFLAGS=-Wall -Wextra -I.


elysian-socks.o: elysian-socks.c
	$(CC) $(CFLAGS) -c $< -o $@

example: elysian-socks.o example.c
	$(CC) $(CFLAGS) $^ -o $@

clean:
	rm -f elysian-socks.o example

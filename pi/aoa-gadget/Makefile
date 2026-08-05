CC ?= gcc
CFLAGS ?= -O2 -Wall -Wextra

aoa_gadget: aoa_gadget.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f aoa_gadget aoa_capture.bin

.PHONY: clean

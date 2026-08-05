CC ?= gcc
CFLAGS ?= -O2 -Wall -Wextra

all: aoa_gadget aoa_gadget_twostage

aoa_gadget: aoa_gadget.c
	$(CC) $(CFLAGS) -o $@ $<

aoa_gadget_twostage: aoa_gadget_twostage.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f aoa_gadget aoa_gadget_twostage aoa_capture.bin

.PHONY: all clean

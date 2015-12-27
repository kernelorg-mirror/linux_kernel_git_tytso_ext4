CFLAGS=-g -O


all: ext4-crypto-cp

ext4-crypto-cp: ext4-crypto-cp.c
	cc -static -m32 $(CFLAGS) -o $@ $<

install-test-progs: ext4-crypto-cp
	mount -t ext4 /dev/closure/test-4k /mnt
	cp ext4-crypto-cp test-crypto-cp /mnt
	umount /mnt

clean:
	rm ext4-crypto-cp

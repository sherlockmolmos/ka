CFLAGS = -Wall -DKYBER_K=2
LDFLAGS = -lcrypto
COMMONC = printhex.c randombytes.c common.c kem.c indcpa.c polyvec.c poly.c ntt.c cbd.c reduce.c verify.c fips202.c symmetric-shake.c

all: client server libkyber512aes128

client: 
	cc $(CFLAGS) client.c $(COMMONC) -o client $(LDFLAGS)

server:
	cc $(CFLAGS) server.c $(COMMONC) -o server $(LDFLAGS)

libkyber512aes128:
	cc -shared -fPIC -DKYBER_K=2 $(COMMONC) -o libKyber512Aes128.so $(LDFLAGS)

main2:
	cc $(CFLAGS) main2.c $(COMMONC) -o main2 $(LDFLAGS)

install: libkyber512aes128
	install -c -m 644 libKyber512Aes128.so /usr/lib/
	install -d /usr/include/kyber512aes128
	install -c -m 644 *.h /usr/include/kyber512aes128
	install -d /home/veins/.key
	./server generatekey
	./client generatekey
	chown veins /home/veins/.key/server.pk /home/veins/.key/server.sk
	chmod 600 /home/veins/.key/server.pk /home/veins/.key/server.sk
	ldconfig

clean:
	rm -f *.o *.so server client main main2

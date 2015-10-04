all:
	mkdir -p bin
	gcc -g -o bin/mpdnfc mpdnfc.c -lnfc

clean:
	rm -f bin/*


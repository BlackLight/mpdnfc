all:
	mkdir -p bin
	gcc -g -o bin/nfc_detect nfc_detect.c -lnfc

clean:
	rm bin/*


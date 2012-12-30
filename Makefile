CC=gcc
CFLAGS=-I.

all: catimageinfo postimage echo_server

echo_server: echo_server.c
	$(CC) -o echo_server echo_server.c
    
catimageinfo: catimageinfo.c
	mkdir images
	$(CC) -o catimageinfo catimageinfo.c -lpcap -lcurl -pthread
    
postimage: postimage.c
	$(CC) -o postimage postimage.c -lcurl
    
clean:
	rm -rf ./images
	rm -rf postimage echo_server catimageinfo




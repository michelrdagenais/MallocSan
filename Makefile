
OLX=$(HOME)/lib/libolx
PATCH=$(HOME)/lib/libpatch
CAPSTONE=/usr/include

libdw: 
	gcc -c -Wall -fPIC -g dw-log.c -o dw-log.o
	gcc -c -Wall -fPIC -g dw-protect.c -o dw-protect.o
	gcc -c -Wall -fPIC -g -I $(OLX)/include  -I $(PATCH)/include -I $(CAPSTONE)/capstone dw-disassembly.c -o dw-disassembly.o
	gcc -c -Wall -fPIC -g dw-wrap-glibc.c -o dw-wrap-glibc.o
	gcc -c -Wall -fPIC -g  -I $(PATCH)/include dw-preload.c -o dw-preload.o
	gcc -shared -g -o libdatawatch.so dw-log.o dw-protect.o dw-disassembly.o dw-wrap-glibc.o dw-preload.o -lcapstone -L $(OLX)/lib/ -lolx -L $(PATCH)/lib/ -lpatch
	gcc -c -Wall -g simple.c -o simple.o
	gcc -g -o simple simple.o
	gcc -g -o simple-dw simple.o dw-log.o dw-protect.o dw-disassembly.o dw-wrap-glibc.o dw-preload.o -lcapstone -L $(OLX)/lib/ -lolx -L $(PATCH)/lib/ -lpatch
        

clean:
	-rm *.o *.so simple simple-dw

all : send_arp

send_arp: main.o
	gcc -o send_arp main.o -lpcap

main.o: send_arp.c my_send_arp.h
	gcc -c -o main.o send_arp.c 

clean:
	rm -f send_arp
	rm -f *.o

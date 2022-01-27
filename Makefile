#Makefile
all: airodump

airodump: 
				g++ main.cpp airodump.cpp -o airodump -lpcap -lpthread

clean:
		rm -f airodump
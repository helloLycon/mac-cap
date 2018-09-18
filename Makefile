#CC = arm-linux-gnueabihf-gcc-4.7
CC = mips-openwrt-linux-g++
#CC = gcc
PROGRAM = mac_cap
#CC = arm-linux-gnueabihf-gcc-4.7    #a10
#PROGRAM = a10_pcap

all: 
	$(CC) $(CFLAG) *.cpp -lpcap -o $(PROGRAM)


clean:
	@rm *.o *~ -f $(PROGRAM)  

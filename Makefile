PROGRAM = cap

all:
	@echo 'usage: make <mips/arm>'

mips: 
	mips-openwrt-linux-g++ $(CFLAG) *.cpp -lpcap -lpthread -o $(PROGRAM).mips

arm:
	g++ $(CFLAG) *.cpp -I./ -L/usr/lib/arm-linux-gnueabihf/ -lpcap -lpthread -o $(PROGRAM).arm

clean:
	rm *.o *~ -f $(PROGRAM)  

PROGRAM = mac-cap

all:
	@echo 'usage: make <mips/arm>'

mips: 
	mips-openwrt-linux-g++ $(CFLAG) *.cpp -lpcap -o $(PROGRAM)

arm:
	g++ $(CFLAG) *.cpp -I./ -L/usr/lib/arm-linux-gnueabihf/ -lpcap  -o $(PROGRAM)

clean:
	rm *.o *~ -f $(PROGRAM)  

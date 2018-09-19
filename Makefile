PROGRAM = mac_cap

mips: 
	mips-openwrt-linux-g++ $(CFLAG) *.cpp -lpcap -o $(PROGRAM)

arm:
	g++ $(CFLAG) *.cpp -I./ -L/usr/lib/arm-linux-gnueabihf/ -lpcap  -o $(PROGRAM)

clean:
	rm *.o *~ -f $(PROGRAM)  

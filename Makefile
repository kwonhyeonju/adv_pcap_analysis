all: adv_pcap_analysis

adv_pcap_analysis: main.o
	g++ -o adv_pcap_analysis main.o -lpcap

main.o: main.cpp
	g++ -c -o main.o main.cpp

clean:
	rm -f *.o adv_pcap_analysis

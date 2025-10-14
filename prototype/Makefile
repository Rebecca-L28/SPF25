all: sdls

spacecraft: spacecraft/spacecraft.c
	gcc -o spacecraft/spacecraft spacecraft/spacecraft.c

ground_station: ground_station/ground_station.c
	gcc -o ground_station/ground_station ground_station/ground_station.c

sdls: sdls/sdls.c
	gcc -o sdls/sdls sdls/sdls.c -lssl -lcrypto
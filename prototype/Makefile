all: sdls

spacecraft: spacecraft/spacecraft.c
	gcc -o spacecraft/spacecraft spacecraft/spacecraft.c

ground_station: ground_station/ground_station.c
	gcc -o ground_station/ground_station ground_station/ground_station.c

sdls: sdls/sdls_showcase.c sdls/sdls.h sdls/sdls_helper.h sdls/security_association.h
	gcc -o sdls/sdls sdls/sdls_showcase.c -lssl -lcrypto
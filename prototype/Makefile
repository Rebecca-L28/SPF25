all: sdls bundle

spacecraft: spacecraft/spacecraft.c
	gcc -o spacecraft/spacecraft spacecraft/spacecraft.c

ground_station: ground_station/ground_station.c
	gcc -o ground_station/ground_station ground_station/ground_station.c

sdls: sdls/sdls_showcase.c sdls/sdls.h sdls/sdls_helper.h sdls/security_association.h
	gcc -o sdls/sdls sdls/sdls_showcase.c -lssl -lcrypto

bundle: bundle/bundle.c bundle/bundle_helper.h bundle/bundle.h
	gcc -o bundle/bundle bundle/bundle.c -lssl -lcrypto

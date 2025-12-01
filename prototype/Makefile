all: sdls bundle

sdls: sdls/sdls_showcase.c sdls/sdls.h sdls/sdls_helper.h sdls/security_association.h
	gcc -o sdls/sdls sdls/sdls_showcase.c -lssl -lcrypto

bundle: bundle/bundle.c bundle/bundle_helper.h bundle/bundle.h bundle/bundle_canocalization.h bundle/bundle_security.h
	gcc -o bundle/bundle bundle/bundle.c -lssl -lcrypto

// SDLS Security Association structure
#pragma once
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stddef.h>
#include <openssl/crypto.h>
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/params.h>

// Security Association structure
typedef struct {
    // Global Virtual Channel ID
    unsigned int GVCID;
    // Global Multiplexer Access Point ID
    unsigned int GMAP_ID;
    // Security Parameter Index (16 bits)
    uint16_t SPI;
    // SA service type
    // 0: Authentication only
    // 1: Encryption only
    // 2: Authentication and Encryption
    uint8_t SA_service_type;
    // Sequence Number length in Security Header (bits)
    size_t SA_length_SN;
    // Initialisation Vector length in Security Header (bits)
    size_t SA_length_IV;
    // Padding length in Security Header (bits)
    size_t SA_length_PL;
    // MAC length in Security Trailer (bits)
    size_t SA_length_MAC;

    // Authentication algorithm
    EVP_MAC* SA_authentication_algorithm;
    // Value or index of the authentication key
    unsigned char* SA_authentication_key;
    // Bit mask for Authentication Payload
    unsigned int SA_authentication_mask;
    // Present value of Sequence Number
    uint32_t SA_sequence_number;
    // Sequence number window size
    unsigned int SA_window_size;

    // Encryption algorithm
    const EVP_CIPHER* SA_encryption_algorithm;
    // Value or index of the encryption key
    unsigned char* SA_encryption_key;
    // Present value of IV
    unsigned char* SA_initialization_vector;
} securityAssociation;

// Security Header structure
typedef struct {
    // Security Parameter Index (16 bits)
    unsigned char* SPI;
    // Initialisation Vector (SA_length_IV bits, optional)
    unsigned char* IV;
    // Sequence Number (SA_length_SN bits, optional)
    unsigned char* SN;
    // Padding (SA_length_PL bits, optional)
    unsigned char* PL;
} securityHeader;

// Security Trailer structure
typedef struct {
    // Message Authentication Code (SA_length_MAC bits, optional)
    unsigned char* MAC;
} securityTrailer;

// Transfer frame structure
typedef struct {
    // Security Header
    securityHeader* sh;
    // Data field
    unsigned char* data_field;
    // Security Trailer
    securityTrailer* st;
} transferFrame;

// Process security return structure
typedef struct {
    // Decrypted data_field
    unsigned char* data_field;
    // Verification status
    // 0: not verified
    // 1: verified
    int verified;
} processSecurityReturn;
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
#include <arpa/inet.h>

// Security Association structure
// TODO: Annex A Conformace Met Except:
//          - TM/TC/AOS/USLP Payloads
//          - Archival of MAC/SN failure discards
// TODO: Annex E contains baseline implementations for further testing
typedef struct {
    // Global Virtual Channel ID
    unsigned int GVCID;
    // Global Multiplexer Access Point ID
    unsigned int GMAP_ID;
    // Security Parameter Index
    // Allowed values: 1-65534
    uint16_t SPI;
    // SA service type
    // 0: Authentication only
    // 1: Encryption only
    // 2: Authentication and Encryption
    uint8_t SA_service_type;
    // Sequence Number length in Security Header
    // Allowed values: 2-8 octets (if used)
    uint8_t SA_length_SN;
    // Initialisation Vector length in Security Header
    // Allowed values: 1-32 octets (if used)
    uint8_t SA_length_IV;
    // Padding length in Security Header
    // Allowed values: 1-2 octets (if used)
    uint8_t SA_length_PL;
    // MAC length in Security Trailer
    // Allowed values: 8-64 octets (if used)
    uint8_t SA_length_MAC;

    // Authentication algorithm
    // Allowed algorithms: HMAC, CMAC
    EVP_MAC* SA_authentication_algorithm;
    // Value of the authentication key
    unsigned char* SA_authentication_key;
    // Bit mask for Authentication Payload  TODO: What is the actual (p.40)
    uint8_t SA_authentication_mask;
    // Present value of Sequence Number
    // Allowed values: 0-1.8446744e+19
    uint64_t SA_sequence_number;
    // Sequence number window size
    // Allowed values: 1-(1.8446744e+19 - 1)
    uint64_t SA_window_size;

    // Encryption algorithm
    // Allowed algorithms: AES-CTR, AES-GCM
    EVP_CIPHER* SA_encryption_algorithm;
    // Value of the encryption key
    unsigned char* SA_encryption_key;
    // Value of the initilization vector
    unsigned char* SA_initialization_vector;
} securityAssociation;

// Security Header structure
typedef struct {
    // Security Parameter Index (2 octets)
    uint16_t SPI;
    // Initialisation Vector (SA_length_IV octets, optional)
    unsigned char* IV;
    // Sequence Number (SA_length_SN octets, optional)
    unsigned char* SN;
    // Padding (SA_length_PL octets, optional)
    unsigned char* PL;
} securityHeader;

// Security Trailer structure
typedef struct {
    // Message Authentication Code (SA_length_MAC octets, optional)
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
    uint8_t verification_status;
    // Verification Status Code
    // 0: no failure
    // 1: invalid SPI
    // 2: MAC verification failure
    // 3: anti-replay sequence number failure
    // 4: padding error
    uint8_t verification_code;
} processSecurityReturn;
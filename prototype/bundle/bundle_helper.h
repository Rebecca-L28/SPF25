// bundle_helper.h will have the helper functions for BSP functionality
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include "bundle.h"

// hardcoded HMAC key, 32 bytes
const unsigned char* HMAC_KEY = (unsigned char*)"01234567890123456789012345678901";
// hardcoded AES key, 32 bytes
const unsigned char* AES_KEY  = (unsigned char*)"01234567890123456789012345678901";

// encodes uint64_t into SDNV format
// returns malloced buffer and sets the encoded_len variable
uint8_t* encode_sdnv(uint64_t value, size_t* encoded_len) {
    // temp buffer - max SDNV size for 64-bit int is 10 bytes
    uint8_t temp[10];
    int i = 0;
    // extract 7 bits each time for the least significant end
    // store in temp in reverse order - LSB first
    do {
        // mask lowest 7 bits
        temp[i++] = value & 0x7F;
        // shift right for next 7 bits
        value >>= 7;
        // stop when all bits are processed
    } while (value > 0);

    // total number of SDNV bytes
    *encoded_len = i;
    // allocate result buffer size
    uint8_t* result = malloc(i);
    // reverse the order - SDNV is big-endian (most significant first)
    for (int j = 0; j < i; j++) {
        // copy from temp in reverse
        result[j] = temp[i - j - 1];
        // all but the last byte, set continuation bit (MSB = 1)
        // more bytes follow
        if (j < i - 1) {
            result[j] |= 0x80;
        }
    }
    // return result, must be freed after calling
    return result;
}

// decodes SDNV into buffer
// returns decoded value and sets the encoded_len variable
uint64_t decode_sdnv(const uint8_t* buffer, size_t* consumed_len) {
    // this is the final decoded int
    uint64_t value = 0;
    // byte counter
    size_t i = 0;
    while (1) {
        // shift current value left by 7 bits for the next group
        // OR the next 7 bits from the buffer
        value = (value << 7) | (buffer[i] & 0x7F);
        // if MSB is 0, last byte
        if ((buffer[i] & 0x80) == 0) {
            break;
        }
        // move to next byte
        i++;
    }
    // total bytes used in decoding
    *consumed_len = i + 1;
    // return the decoded integer
    return value;
}

// serialize the bundle
uint8_t* serializeBundle(bundle* b, size_t* length) {
    size_t total_len = 0;
    // temp buffer
    uint8_t* buffer = malloc(2048);

    // serialize primary block which is the bundle metadata
    // version is 1 byte
    buffer[total_len++] = b->primary->version;

    // encode the processing flags since RFC 5050 says it's an SDNV
    size_t sdnv_len;
    // call the encoding function
    uint8_t* sdnv = encode_sdnv(b->primary->proc_flags, &sdnv_len);
    // copy the encoded flags
    memcpy(buffer + total_len, sdnv, sdnv_len);
    total_len += sdnv_len;
    // free the temp SDNV buffer
    free(sdnv);

    // serialize the enpoint identifiers (EIDs) as null-term strings
    const char* eids[] = {
            // all EID variables
            b->primary->dest_eid,
            b->primary->source_eid,
            b->primary->report_to_eid,
            b->primary->custodian_eid
    };
    // iterate through the above EID variables
    for (int i = 0; i < 4; i++) {
        // include the null terminator
        size_t eid_len = strlen(eids[i]) + 1;
        // copy the EID string
        memcpy(buffer + total_len, eids[i], eid_len);
        total_len += eid_len;
    }

    // RFC 5050 has timestamp, sequence number, and lifetime as SDNVs
    // use the same format as encoding the processing flags
    // call encode
    sdnv = encode_sdnv(b->primary->creation_timestamp, &sdnv_len);
    // copy the timestamp
    memcpy(buffer + total_len, sdnv, sdnv_len);
    total_len += sdnv_len;
    // free the buffer
    free(sdnv);
    // repeat for sequence number
    sdnv = encode_sdnv(b->primary->sequence_number, &sdnv_len);
    memcpy(buffer + total_len, sdnv, sdnv_len);
    total_len += sdnv_len;
    free(sdnv);
    // repeat for lifetime
    sdnv = encode_sdnv(b->primary->lifetime, &sdnv_len);
    memcpy(buffer + total_len, sdnv, sdnv_len);
    total_len += sdnv_len;
    free(sdnv);

    // done serializing primary block

    // serialize payload block
    // block type (1 = payload)
    buffer[total_len++] = b->payload->block_type;
    // processing flags are SDNV, follow same steps as above
    sdnv = encode_sdnv(b->payload->proc_flags, &sdnv_len);
    memcpy(buffer + total_len, sdnv, sdnv_len);
    total_len += sdnv_len;
    free(sdnv);
    // block length is also SDNV
    sdnv = encode_sdnv(b->payload->block_length, &sdnv_len);
    memcpy(buffer + total_len, sdnv, sdnv_len);
    total_len += sdnv_len;
    free(sdnv);
    memcpy(buffer + total_len, b->payload->payload, b->payload->payload_len);
    total_len += b->payload->payload_len;

    // if there is a PIB (payload integrity block), serialize it
    if (b->pib) {
        buffer[total_len++] = b->pib->block_type;
        // processing flags are SDNV
        sdnv = encode_sdnv(b->pib->proc_flags, &sdnv_len);
        memcpy(buffer + total_len, sdnv, sdnv_len);
        total_len += sdnv_len;
        free(sdnv);
        // block length is SDNV
        sdnv = encode_sdnv(b->pib->block_length, &sdnv_len);
        memcpy(buffer + total_len, sdnv, sdnv_len);
        total_len += sdnv_len;
        free(sdnv);
        memcpy(buffer + total_len, b->pib->security_data, b->pib->security_data_len);
        total_len += b->pib->security_data_len;
    }

    // if there is a PCB (payload confidentiality block), serialize it
    if (b->pcb) {
        buffer[total_len++] = b->pcb->block_type;
        // SDNV processing flags
        sdnv = encode_sdnv(b->pcb->proc_flags, &sdnv_len);
        memcpy(buffer + total_len, sdnv, sdnv_len);
        total_len += sdnv_len;
        free(sdnv);
        // SDNV block length
        sdnv = encode_sdnv(b->pcb->block_length, &sdnv_len);
        memcpy(buffer + total_len, sdnv, sdnv_len);
        total_len += sdnv_len;
        free(sdnv);
        memcpy(buffer + total_len, b->pcb->security_data, b->pcb->security_data_len);
        total_len += b->pcb->security_data_len;
    }
    // lastly, copy to buffer and return
    uint8_t* final = malloc(total_len);
    memcpy(final, buffer, total_len);
    // free temp buffer
    free(buffer);
    // set the output length
    *length = total_len;
    return final;
}

// deserialize the bundle
bundle* deserializeBundle(const uint8_t* buffer, size_t length) {
    size_t offset = 0;
    // allocate for bundle container
    bundle* b = malloc(sizeof(bundle));
    // allocate for the primary block
    b->primary = malloc(sizeof(bundlePrimaryBlock));
    // allocate for the payload block
    b->payload = malloc(sizeof(bundlePayloadBlock));
    // initialize the optional PIB and PCB
    b->pib = NULL;
    b->pcb = NULL;

    // parse the primary block
    // read the version
    b->primary->version = buffer[offset++];

    size_t sdnv_len;
    // decode processing flags
    b->primary->proc_flags = decode_sdnv(buffer + offset, &sdnv_len);
    offset += sdnv_len;

    // parse all the EID variables
    char* eid_buf = (char*)(buffer + offset);
    b->primary->dest_eid = strdup(eid_buf);
    offset += strlen(eid_buf) + 1;
    eid_buf = (char*)(buffer + offset);
    b->primary->source_eid = strdup(eid_buf);
    offset += strlen(eid_buf) + 1;
    eid_buf = (char*)(buffer + offset);
    b->primary->report_to_eid = strdup(eid_buf);
    offset += strlen(eid_buf) + 1;
    eid_buf = (char*)(buffer + offset);
    b->primary->custodian_eid = strdup(eid_buf);
    offset += strlen(eid_buf) + 1;

    // decode the timestamp, sequence number, and lifetime
    b->primary->creation_timestamp = decode_sdnv(buffer + offset, &sdnv_len);
    offset += sdnv_len;
    b->primary->sequence_number = decode_sdnv(buffer + offset, &sdnv_len);
    offset += sdnv_len;
    b->primary->lifetime = decode_sdnv(buffer + offset, &sdnv_len);
    offset += sdnv_len;

    // parse the payload block
    b->payload->block_type = buffer[offset++];
    // decode the processing flags
    b->payload->proc_flags = decode_sdnv(buffer + offset, &sdnv_len);
    offset += sdnv_len;
    // decode the block length
    b->payload->block_length = decode_sdnv(buffer + offset, &sdnv_len);
    offset += sdnv_len;
    // payload length = block length
    b->payload->payload_len = b->payload->block_length;
    b->payload->payload = malloc(b->payload->payload_len);
    // copy the payload
    memcpy(b->payload->payload, buffer + offset, b->payload->payload_len);
    offset += b->payload->payload_len;

    // parse the PIB and PCB blocks if applicable
    while (offset < length) {
        // read block type
        uint8_t block_type = buffer[offset++];
        // decode processing flags
        uint64_t proc_flags = decode_sdnv(buffer + offset, &sdnv_len);
        offset += sdnv_len;
        // decode the block length
        uint64_t block_length = decode_sdnv(buffer + offset, &sdnv_len);
        offset += sdnv_len;
        uint8_t* block_data = malloc(block_length);
        memcpy(block_data, buffer + offset, block_length);
        offset += block_length;

        // create the security block structure and populate it with the correct values
        bundleSecurityBlock* sec = malloc(sizeof(bundleSecurityBlock));
        sec->block_type = block_type;
        sec->proc_flags = proc_flags;
        sec->block_length = block_length;
        sec->security_data_len = block_length;
        sec->security_data = block_data;

        // when block type is 2, it is a PIB
        if (block_type == 2) {
            b->pib = sec;
        }
            // when block type is 3, it is a PCB
        else if (block_type == 3) {
            b->pcb = sec;
        }
            // else free the block
        else {
            free(block_data);
            free(sec);
        }
    }
    // return the reconstructed bundle
    return b;
}

// print the bundle information
void printBundle(bundle* b) {
    // format the printing of the primary and payload bundle blocks
    printf("Version: %d\n", b->primary->version);
    printf("Source EID: %s\n", b->primary->source_eid);
    printf("Destination EID: %s\n", b->primary->dest_eid);
    printf("Report-to EID: %s\n", b->primary->report_to_eid);
    printf("Custodian EID: %s\n", b->primary->custodian_eid);
    printf("Creation Time: %lu\n", b->primary->creation_timestamp);
    printf("Sequence Number: %lu\n", b->primary->sequence_number);
    printf("Lifetime: %lu\n", b->primary->lifetime);
    printf("Payload (%zu bytes): %.*s\n",
           b->payload->payload_len,
           (int)b->payload->payload_len,
           b->payload->payload);
}

// clean up memory
void freeBundle(bundle* b) {
    // if bundle ptr is NULL, nothing to free
    if (b == NULL) {
        return;
    }
    // free primary block and all fields
    if (b->primary) {
        // free all EID strings
        free(b->primary->source_eid);
        free(b->primary->dest_eid);
        free(b->primary->report_to_eid);
        free(b->primary->custodian_eid);
        // free dictionary since it was dynamically allocated
        free(b->primary->dictionary);
        // free block itself
        free(b->primary);
    }
    // free payload block and buffer
    if (b->payload) {
        // free payload data
        free(b->payload->payload);
        // free payload block structure
        free(b->payload);
    }
    // free bundle container
    free(b);
}


// bundle security (PIB and PCB)

// applies the integrity with PIB and/or the encryption with PCB to the payload
void applyBundleSecurity(bundle* b, int use_pib, int use_pcb) {
    if (use_pcb) {
        // allocate and initialize the PCB
        b->pcb = malloc(sizeof(bundleSecurityBlock));
        // block type is 3 for PCB
        b->pcb->block_type = 3;
        // no flags
        b->pcb->proc_flags = 0;

        // generate initialization vector (IV) for AES-GCM
        // 96-bit IV for GCM
        unsigned char iv[12];
        // use random for secure IV
        RAND_bytes(iv, sizeof(iv));

        // set up AES-256-GCM encryption
        // create cipher
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        // initialize cipher type
        EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
        // set IV length
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, sizeof(iv), NULL);
        // set encryption key and IV
        EVP_EncryptInit_ex(ctx, NULL, NULL, AES_KEY, iv);

        // encrypt the payload
        int len;
        // allocate space for ciphertext and the tag
        unsigned char* ciphertext = malloc(b->payload->payload_len + 16);
        // encrypt the payload
        EVP_EncryptUpdate(ctx, ciphertext, &len, b->payload->payload, b->payload->payload_len);
        int ciphertext_len = len;
        // finalize the encryption
        EVP_EncryptFinal_ex(ctx, ciphertext + len, &len);
        ciphertext_len += len;

        // extract the authentication tag which is used for checking integrity during decryption
        unsigned char tag[16];
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, sizeof(tag), tag);

        // store the IV, ciphertext, and tag in the PCB block
        b->pcb->security_data_len = ciphertext_len + sizeof(tag) + sizeof(iv);
        b->pcb->security_data = malloc(b->pcb->security_data_len);
        // IV is first
        memcpy(b->pcb->security_data, iv, sizeof(iv));
        // ciphertext next
        memcpy(b->pcb->security_data + sizeof(iv), ciphertext, ciphertext_len);
        // tag last
        memcpy(b->pcb->security_data + sizeof(iv) + ciphertext_len, tag, sizeof(tag));
        b->pcb->block_length = b->pcb->security_data_len;

        // replace the original payload with the encrypted version
        free(b->payload->payload);
        b->payload->payload = malloc(ciphertext_len);
        memcpy(b->payload->payload, ciphertext, ciphertext_len);
        b->payload->payload_len = ciphertext_len;

        // clean up the ciphertext
        free(ciphertext);
        EVP_CIPHER_CTX_free(ctx);
    }

    if (use_pib) {
        // allocate and initialize the PIB
        b->pib = malloc(sizeof(bundleSecurityBlock));
        // if block type is 2, PIB
        b->pib->block_type = 2;
        // no flags
        b->pib->proc_flags = 0;

        // compute the HMAC-SHA256 over the payload
        // fetch the HMAC implementation
        EVP_MAC* mac = EVP_MAC_fetch(NULL, "HMAC", NULL);
        // create new MAC
        EVP_MAC_CTX* ctx = EVP_MAC_CTX_new(mac);
        OSSL_PARAM params[] = {
                OSSL_PARAM_construct_utf8_string("digest", "SHA256", strlen("SHA256")),
                OSSL_PARAM_construct_end()
        };

        // initialize with the key and digest
        EVP_MAC_init(ctx, HMAC_KEY, strlen((char*)HMAC_KEY), params);
        // feed in the payload
        EVP_MAC_update(ctx, b->payload->payload, b->payload->payload_len);

        // finalize and store the MAC
        size_t mac_len;
        // get the output length
        EVP_MAC_final(ctx, NULL, &mac_len, 0);
        b->pib->security_data = malloc(mac_len);
        // write the MAC output
        EVP_MAC_final(ctx, b->pib->security_data, &mac_len, mac_len);
        b->pib->security_data_len = mac_len;
        b->pib->block_length = mac_len;

        // clean up allocated memory
        EVP_MAC_CTX_free(ctx);
        EVP_MAC_free(mac);
    }
}

// verifies the integrity and/or decrypts the payload
int processBundleSecurity(bundle* b, int verify_pib, int decrypt_pcb) {
    if (verify_pib && b->pib) {
        // recompute the HMAC over the current payload
        EVP_MAC* mac = EVP_MAC_fetch(NULL, "HMAC", NULL);
        EVP_MAC_CTX* ctx = EVP_MAC_CTX_new(mac);
        OSSL_PARAM params[] = {
                OSSL_PARAM_construct_utf8_string("digest", "SHA256", strlen("SHA256")),
                OSSL_PARAM_construct_end()
        };

        EVP_MAC_init(ctx, HMAC_KEY, strlen((char*)HMAC_KEY), params);
        EVP_MAC_update(ctx, b->payload->payload, b->payload->payload_len);

        // finalize and compare with the stored MAC
        size_t mac_len;
        unsigned char* computed_mac = malloc(b->pib->security_data_len);
        EVP_MAC_final(ctx, computed_mac, &mac_len, b->pib->security_data_len);

        // constant time comparision
        int verified = memcmp(computed_mac, b->pib->security_data, mac_len) == 0;
        free(computed_mac);
        EVP_MAC_CTX_free(ctx);
        EVP_MAC_free(mac);

        // if integrity check fails, MAC verification fails
        if (!verified) {
            fprintf(stderr, "[ERROR] MAC verification failed\n");
            return 0;
        }
            // else the MAC is verified
        else {
            printf("MAC verified\n");
        }
    }

    if (decrypt_pcb && b->pcb) {
        // extract the IV, ciphertext, and tag from the PCB
        // first 12 bytes
        unsigned char* iv = b->pcb->security_data;
        // after the IV is the ciphertext
        unsigned char* ciphertext = b->pcb->security_data + 12;
        // last 16 bytes if the tag
        unsigned char* tag = b->pcb->security_data + b->pcb->security_data_len - 16;
        int ciphertext_len = b->pcb->security_data_len - 12 - 16;

        // set up AES-GCM decryption
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL);
        EVP_DecryptInit_ex(ctx, NULL, NULL, AES_KEY, iv);

        // decrypt the ciphertext
        unsigned char* plaintext = malloc(ciphertext_len);
        int len;
        EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len);
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag);

        // finalize the decryption and verify the tag
        // if this executes, authentication has failed
        if (EVP_DecryptFinal_ex(ctx, plaintext + len, &len) != 1) {
            fprintf(stderr, "[ERROR] Decryption failed\n");
            free(plaintext);
            EVP_CIPHER_CTX_free(ctx);
            return 0;
        }

        // replace the encrypted payload with plaintext
        int plaintext_len = len + ciphertext_len;
        free(b->payload->payload);
        b->payload->payload = malloc(plaintext_len);
        memcpy(b->payload->payload, plaintext, plaintext_len);
        b->payload->payload_len = plaintext_len;

        // clean up allocated memory
        free(plaintext);
        EVP_CIPHER_CTX_free(ctx);
        // print a success message
        printf("Decryption successful\n");
    }

    return 1;
}

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
        memcpy(buffer + total_len, b->pib->security_result, b->pib->security_result_len);
        total_len += b->pib->security_result_len;
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
        memcpy(buffer + total_len, b->pcb->security_result, b->pcb->security_result_len);
        total_len += b->pcb->security_result_len;
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
        sec->security_result_len = block_length;
        sec->security_result = block_data;

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
        b->pcb->security_result_len = ciphertext_len + sizeof(tag) + sizeof(iv);
        b->pcb->security_result = malloc(b->pcb->security_result_len);
        // IV is first
        memcpy(b->pcb->security_result, iv, sizeof(iv));
        // ciphertext next
        memcpy(b->pcb->security_result + sizeof(iv), ciphertext, ciphertext_len);
        // tag last
        memcpy(b->pcb->security_result + sizeof(iv) + ciphertext_len, tag, sizeof(tag));
        b->pcb->block_length = b->pcb->security_result_len;

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
        b->pib->security_result = malloc(mac_len);
        // write the MAC output
        EVP_MAC_final(ctx, b->pib->security_result, &mac_len, mac_len);
        b->pib->security_result_len = mac_len;
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
        unsigned char* computed_mac = malloc(b->pib->security_result_len);
        EVP_MAC_final(ctx, computed_mac, &mac_len, b->pib->security_result_len);

        // constant time comparision
        int verified = memcmp(computed_mac, b->pib->security_result, mac_len) == 0;
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
        unsigned char* iv = b->pcb->security_result;
        // after the IV is the ciphertext
        unsigned char* ciphertext = b->pcb->security_result + 12;
        // last 16 bytes if the tag
        unsigned char* tag = b->pcb->security_result + b->pcb->security_result_len - 16;
        int ciphertext_len = b->pcb->security_result_len - 12 - 16;

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

// to do canonicalization, I used the RFC 6257 PDF section 3.4

// SOURCE: https://www.rfc-editor.org/rfc/pdfrfc/rfc6257.txt.pdf

// create a helper function that will append the raw bytes to the buffer
static void appendBytes(uint8_t **buf, size_t *len, const uint8_t *data, size_t data_len) {
    // allocate or rezie the buffer to hold the existing data plus new data
    *buf = (uint8_t*)realloc(*buf, (*len) + data_len);
    // copy the new bytes at the end
    memcpy (*buf + (*len), data, data_len);
    // update the length
    *len += data_len;
}

// create a helper that will append just one byte
static void appendOneByte(uint8_t **buf, size_t *len, uint8_t v) {
    appendBytes(buf, len, &v, 1);
}

// create a helper that will append a 4-btye big-end unsigned int
static void appendBigEndFourByteUnsInt(uint8_t **buf, size_t *len, uint32_t v) {
    // convert to big endian
    uint8_t out[4];
    // put most-sig byte first
    out[0] = (v >> 24) & 0xFF;
    out[1] = (v >> 16) & 0xFF;
    out[2] = (v >> 8) & 0xFF;
    out[3] = (v) & 0xFF;
    appendBytes (buf, len, out, 4);
}

// create a helper that appends an 8-byte big endian unsigned int
static void appendBigEndEightByteUnsInt(uint8_t **buf, size_t *len, uint64_t v) {
    uint8_t out[8];
    // put most-sig byte first
    out[0] = (v >> 56) & 0xFF;
    out[1] = (v >> 48) & 0xFF;
    out[2] = (v >> 40) & 0xFF;
    out[3] = (v >> 32) & 0xFF;
    out[4] = (v >> 24) & 0xFF;
    out[5] = (v >> 16) & 0xFF;
    out[6] = (v >> 8) & 0xFF;
    out[7] = (v) & 0xFF;
    appendBytes(buf, len, out, 8);
}

// create a helper that will append an SDNV in its encoded form, which is used by strict canonicalization
static void appendSDNVEnc(uint8_t **buf, size_t *len, uint64_t value) {
    size_t encLen = 0;
    uint8_t* enc = encode_sdnv(value, &encLen);
    appendBytes(buf, len, enc, encLen);
    free(enc);
}

// create a helper function to deal with the strict canonicalization security blocks
static void appendStrSecBlock(bundleSecurityBlock *sb, uint8_t ciphersuite_type, uint8_t **out, size_t *out_len) {
    if (!sb) {
        return;
    }

    // block type
    appendOneByte(out, out_len, sb->block_type);
    // proc_flags SDNV
    appendSDNVEnc(out, out_len, sb->proc_flags);
    // block_length SDNV
    appendSDNVEnc(out, out_len, sb->block_length);
    // if this is not the ciphersuite being verified, append security_result bytes
    if (sb->ciphersuite_id != ciphersuite_type) {
        if (sb->security_result && sb->security_result_len > 0) {
            appendBytes(out, out_len, sb->security_result, sb->security_result_len);
        }
    }
}

// create helper function to deal with mutable canonicalization security blocks
static void appendMutSecBlock(bundleSecurityBlock *sb, uint64_t BLOCK_FLAGS_MASK, uint8_t **out, size_t *out_len) {
    if (!sb) {
        return;
    }

    // block type
    appendOneByte(out, out_len, sb->block_type);
    // proc_flags -> unpack to 8 bytes and mask reserved/mutable bits
    uint64_t masked = sb->proc_flags & BLOCK_FLAGS_MASK;
    appendBigEndEightByteUnsInt(out, out_len, masked);
    // block_length as 8-byte unpacked value per RFC 6257
    appendBigEndEightByteUnsInt(out, out_len, sb->block_length);
    // append security_result bytes
    if (sb->security_result && sb->security_result_len > 0) {
        appendBytes(out, out_len, sb->security_result, sb->security_result_len);
    }
}


// STRICT CANONICALIZATION
// the RFC 6257 section 3.4.1 outlines what is needed here
// concatenate all the blocks in the order that they are presented, but omit the security_result data bytes for blocks
// of the ciphersuite being verified
// include the security_result_len field (not set to 0)
// the arguments will be:
// b --> pointer to bundle, ciphersuite_type --> ciphersuite ID being verified, out --> receives malloc'd buffer with
// canonical bytes (must be freed), out_len --> receives length of buffer
// success = 1, fail = 0
int canonicalizeStrict(bundle *b, uint8_t ciphersuite_type, uint8_t **out, size_t *out_len) {
    // check if valid
    if (!b || !out || !out_len) {
        return 0;
    }

    // initialize the output buffer and length
    *out = NULL;
    *out_len = 0;

    // primary block
    // version byte is one byte
    appendOneByte(out, out_len, b->primary->version);

    // processing flags, which are SDNVs
    appendSDNVEnc(out, out_len, b->primary->proc_flags);

    // endpoint IDs as null-term strings
    // RFC 6257 figure 5 uses lengths and references into dictionary, for strict canonicalizations,
    // these bytes are concated as they are stored
    const char *endpointIDs[4] = {
            b->primary->dest_eid ? b->primary->dest_eid : "",
            b->primary->source_eid ? b->primary->source_eid : "",
            b->primary->report_to_eid ? b->primary->report_to_eid : "",
            b->primary->custodian_eid ? b->primary->custodian_eid : ""
    };
    for (int i = 0; i < 4; i++) {
        // include null term just like in the serializeBundle function
        size_t s = strlen(endpointIDs[i] + 1);
        appendBytes(out, out_len, (const uint8_t*)endpointIDs[i], s);
    }

    // creation timesstamp, sequence number, and lifetime in their encoded SDNV form
    appendSDNVEnc(out, out_len, b->primary->creation_timestamp);
    appendSDNVEnc(out, out_len, b->primary->sequence_number);
    appendSDNVEnc(out, out_len, b->primary->lifetime);

    // now the payload and payload security blocks will be appended just like in serializeBundle
    // for strict canonicalization, when encountering a security block where
    // ciphersuite_id == ciphersuite_type, omit the security_result bytes, but include the length

    // append the payload block if present
    if (b->payload) {
        // block type, one byte
        appendOneByte(out, out_len, b->payload->block_type);
        // proc_flags as encoded SDNV
        appendSDNVEnc(out, out_len, b->payload->proc_flags);
        // payload length as encoded SDNV
        appendSDNVEnc(out, out_len, b->payload->block_length);
        // payload bytes
        if (b->payload->payload_len && b->payload->payload) {
            appendBytes(out, out_len, b->payload->payload, b->payload->payload_len);
        }
    }

    // use helper function to append the security block(s) if present
    appendStrSecBlock(b->pib, ciphersuite_type, out, out_len);
    appendStrSecBlock(b->pcb, ciphersuite_type, out, out_len);
    appendStrSecBlock(b->bab, ciphersuite_type, out, out_len);
    appendStrSecBlock(b->bab2, ciphersuite_type, out, out_len);
    appendStrSecBlock(b->esb, ciphersuite_type, out, out_len);

    return 1;
}

// MUTABLE CANONICALIZATION
// the RFC 6257 section 3.4.2 outlines what is needed here
// only primary block canonical fields are included (exclude flags that may change), SDNVs are unpacked to 8-byte fields
// in big endian, primary block canonical length is 4 bytes big endian
// for non-primary blocks included (payload and security blocks):
// proc_flags are unpacked to 8-byte field and masked with 0x77, block_length is 8-byte in big endian, endpoint IDs
// are replaced by textual EIDs
// ESBs are not included, and SDNV fields are unpacked to 8 bytes in big endian
int canonicalizeMut(bundle *b, uint8_t ** out, size_t *out_len) {
    // check if valid
    if (!b || !out || !out_len) {
        return 0;
    }

    // initialize the output buffer and length
    *out = NULL;
    *out_len = 0;

    // masks defined in RFC 6257 3.4.2 for canonicalization
    // zero reserved bits + fragment bit
    const uint64_t PRIMARY_FLAGS_MASK = 0x000000000007C1BEULL;
    // zero reserved + last-block flag
    const uint64_t BLOCK_FLAGS_MASK = 0x0000000000000077ULL;

    // primary block, use figure 5
    // version (one byte)
    appendOneByte(out, out_len, b->primary->version);
    // proc_flags: unpack SDNV to 8-btye field and mask out bits
    // RFC says "The SDNV is unpacked into a fixed-width field, and then ANDed with mask".
    uint64_t pf = b->primary->proc_flags & PRIMARY_FLAGS_MASK;
    // append as 8 bytes in big endian
    appendBigEndEightByteUnsInt(out, out_len, pf);

    // primary block length value (4 bytes, big endian)
    // RFC says this contains the length of the structure in big endian order, since it is unknown until the block
    // is built, it is built into a temp buffer and then prefix the 4-byte length
    uint8_t *primary_body = NULL;
    size_t primary_body_len = 0;

    // EIDs: 4 byte length, and textual value
    const char *dest = b->primary->dest_eid ? b->primary->dest_eid : "";
    appendBigEndFourByteUnsInt(&primary_body, &primary_body_len, (uint32_t) strlen(dest));
    appendBytes(&primary_body, &primary_body_len, (const uint8_t *) dest, strlen(dest));
    const char *src = b->primary->source_eid ? b->primary->source_eid : "";
    appendBigEndFourByteUnsInt(&primary_body, &primary_body_len, (uint32_t) strlen(src));
    appendBytes(&primary_body, &primary_body_len, (const uint8_t *) src, strlen(src));
    const char *rto = b->primary->report_to_eid ? b->primary->report_to_eid : "";
    appendBigEndFourByteUnsInt(&primary_body, &primary_body_len, (uint32_t) strlen(rto));
    appendBytes(&primary_body, &primary_body_len, (const uint8_t *) rto, strlen(rto));

    // creation timestamp, sequence number, and lifetime-> canonicalize as 8-btye unpacked values in big endian
    // RFC said "SDNV values are represented as eight-byte unpacked values".
    appendBigEndEightByteUnsInt(&primary_body, &primary_body_len, b->primary->creation_timestamp);
    // sequence number
    appendBigEndEightByteUnsInt(&primary_body, &primary_body_len, b->primary->sequence_number);
    // lifetime
    appendBigEndEightByteUnsInt(&primary_body, &primary_body_len, b->primary->lifetime);

    // canonical primary block length is the length of the stucture built above
    uint32_t primary_len32 = (uint32_t) primary_body_len;
    // 4-byte length prefix
    appendBigEndFourByteUnsInt(out, out_len, primary_len32);
    // then append the primary body
    appendBytes(out, out_len, primary_body, primary_body_len);
    // free the temp
    free(primary_body);

    // now the payload and payload security blocks will be appended just like in serializeBundle
    // As RFC says: "catenate canonical primary block with the security (PIBs and PCBs only)
    // and payload blocks in the order transmitted."  ESBs are excluded.

    // payload block
    if (b->payload) {
        // block type (one byte)
        appendOneByte(out, out_len, b->payload->block_type);
        // proc_flags unpacked and masked
        uint64_t pflags = b->payload->proc_flags & BLOCK_FLAGS_MASK;
        appendBigEndEightByteUnsInt(out, out_len, pflags);
        // block_length unpacked
        appendBigEndEightByteUnsInt(out, out_len, b->payload->block_length);
        // payload data
        if (b->payload->payload_len && b->payload->payload) {
            appendBytes(out, out_len, b->payload->payload, b->payload->payload_len);
        }
    }

    // use helper function to append the security block(s) if present
    appendMutSecBlock(b->pib, BLOCK_FLAGS_MASK, out, out_len);
    appendMutSecBlock(b->pcb, BLOCK_FLAGS_MASK, out, out_len);

    return 1;
}
#pragma once
#include "bundle.h"

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

// print the bundle information
void printBundle(bundle* b) {
    // format the printing of the primary and payload bundle blocks
    printf("__Primary Block + Payload Block__\n");
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
    printf("\n");
}

// clean up single security block
void freeSecurityBlock(bundleSecurityBlock* sb) {
    if (sb == NULL) {
        return;
    }

    // free eid_reference_list
    if (sb->eid_reference_list) {
        if (sb->eid_reference_list->security_source) {
            free(sb->eid_reference_list->security_source);
        }
        if (sb->eid_reference_list->security_dest) {
            free(sb->eid_reference_list->security_dest);
        }
        free(sb->eid_reference_list);
    }

    // free ciphersuite_params
    for (int i = 0; i < 3; i++) {
        if (sb->ciphersuite_params){
            if (sb->ciphersuite_params[i]) {
                if (sb->ciphersuite_params[i]->value) {
                    free(sb->ciphersuite_params[i]->value);
                }
                free(sb->ciphersuite_params[i]);
            }
        }
    }

    // free security_result
    if (sb->security_result) {
        free(sb->security_result);
    }

    // free the block itself
    free(sb);
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
        if (b->primary->dictionary){
            free(b->primary->dictionary);
        }
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

    // free security blocks
    freeSecurityBlock(b->bab);
    freeSecurityBlock(b->pib);
    freeSecurityBlock(b->pcb);
    freeSecurityBlock(b->bab2);

    // free bundle container
    free(b);
}

// prints a single security block
void printSecurityBlock(unsigned char* typeOfBlock, bundleSecurityBlock* sb) {
    // Check if we have this security block
    if (!sb) {
        printf("__%s__\n", typeOfBlock);
        printf("N/A\n\n");
        return;
    }

    // Print the security block's fields
    printf("__%s__\n", typeOfBlock);
    printf("Block Type: %d\n", sb->block_type);
    printf("Block Length: %d\n", sb->block_length);
    printf("Proc Flags: 0x%X\n", sb->proc_flags);
    printf("Ciphersuite ID: %d\n", sb->ciphersuite_id);
    printf("Ciphersuite Flags: 0x%X\n", sb->ciphersuite_flags);
    printf("Correlator: %d\n", sb->correlator);

    // Print Parameters
    for (int i = 0; i < 3; i++) {
        if (sb->ciphersuite_params[i]) {
            printf("Parameter #%d, Type 0x%X: ", i, sb->ciphersuite_params[i]->type);
            for (int j = 0; j < sb->ciphersuite_params[i]->len; j++) {
                printf("%02X", sb->ciphersuite_params[i]->value[j]);
            }
            printf("\n");
        }
    }

    // Print Security Result
    printf("Security Result (%d bytes): ", sb->security_result_len);
    if (!sb->security_result_len){
        printf("N/A\n\n");
        return;
    }
    for (int i = 0; i < sb->security_result_len; i++) {
        printf("%02X", sb->security_result[i]);
    }
    printf("\n\n");
}

// prints the entire bundle
void printEntireBundle(bundle* b) {
    printf("\n___Bundle Contents___\n");
    printBundle(b);
    printSecurityBlock("BAB (Front)", b->bab);
    printSecurityBlock("PIB", b->pib);
    printSecurityBlock("PCB", b->pcb);
    printSecurityBlock("BAB (Rear)", b->bab2);
    printf("\n");
}

// serialize the bundle
// TODO: needs to be updated
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
// TODO: needs to be updated
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

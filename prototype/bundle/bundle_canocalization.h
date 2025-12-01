#pragma once
#include "bundle_helper.h"

// SOURCE: https://www.rfc-editor.org/rfc/pdfrfc/rfc6257.txt.pdf - Section 3.4

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
    //appendStrSecBlock(b->esb, ciphersuite_type, out, out_len);

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
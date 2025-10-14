#pragma once
#include "security_association.h"

securityAssociation* FindSA(securityAssociation** sa_array, unsigned int sa_array_size, unsigned int GVCID, unsigned int GMAP_ID){
    // Iterate through the SA array to find the matching SA
  for (unsigned int i = 0; i < sa_array_size; i++) {
    // Check if the GVCID matches
    if (sa_array[i]->GVCID != GVCID){
      continue;
    }

    // Check if the GMAP_ID matches, provided it is not 0
    if (GMAP_ID == 0 || sa_array[i]->GMAP_ID != GMAP_ID){
      continue;
    }

    // If both match, return the SA
    return sa_array[i];
  }

  // IF no matching SA were found, then return NULL
  return NULL;
}

void handleOctetPadding(transferFrame* tf, securityAssociation* sa, uint32_t pl, int alignIV, int alignSN, int alignPL, int alignMAC, unsigned char* mac_value){
  // Gather SPI details
  uint16_t spi = sa->SPI;

  // Handle SPI
  tf->sh->SPI = malloc(2);
  tf->sh->SPI[0] = (unsigned char)((spi >> 8) & 0xFF);
  tf->sh->SPI[1] = (unsigned char)(spi & 0xFF);

  // If we want to align the IV
  if (alignIV == 1){
    // Gather current IV details
    size_t padded_len = sa->SA_length_IV/8;
    size_t iv_len = strlen(sa->SA_initialization_vector);
    
    // Handle IV
    unsigned char* padded_iv = malloc(padded_len);
    memcpy(padded_iv, sa->SA_initialization_vector, iv_len);
    size_t padding = padded_len - iv_len;
    if (padding > 0){
      memset(padded_iv + iv_len, 0x00, padding);
    }

    // Set the IV
    tf->sh->IV = malloc(padded_len);
    memcpy(tf->sh->IV, padded_iv, padded_len);

    // Free memory
    free(padded_iv);
  }

  // If we want to align SN
  if (alignSN == 1){
    // Gather current SN details
    uint32_t sn = sa->SA_sequence_number + 1;
    size_t sn_length = sa->SA_length_SN;

    // Handle SN
    tf->sh->SN = malloc(sn_length/8);
    for (size_t i = 0; i < sn_length/8; i++) {
      tf->sh->SN[i] = (unsigned char)((sn >> sn_length - 8 - 8*i) & 0xFF);
    }
  }

  // If we want to align PL
  if (alignPL == 1){
    // Gather current PL details
    size_t pl_length = sa->SA_length_PL;

    // Handle PL
    tf->sh->PL = malloc(pl_length/8);
    for (size_t i = 0; i < pl_length/8; i++) {
      tf->sh->PL[i] = (unsigned char)((pl >> pl_length - 8 - 8*i) & 0xFF);
    }
  }
}

uint32_t handleOctetPaddingReceive(transferFrame* tf, securityAssociation* sa, int handleSPI, int handleSN, int handlePL){
  // Handle SPI
  if (handleSPI == 1){
    unsigned char* spi =  tf->sh->SPI;
    uint32_t s_decoded = 0;
    s_decoded |= (uint32_t)spi[0] << 8;
    s_decoded |= (uint32_t)spi[1];
    return s_decoded;
  }

  // Handle SN
  if (handleSN == 1){
    unsigned char* sn = tf->sh->SN;
    uint32_t sn_decoded = 0;
    for (size_t i = 0; i < sa->SA_length_SN/8; i++) {
      sn_decoded |= (uint32_t)sn[i] << sa->SA_length_SN - 8 - 8*i;
    }
    return sn_decoded;
  }
}

#pragma once
#include "security_association.h"

void p_error(unsigned char* msg){
  printf("[ERROR] %s\n", msg);
  exit(EXIT_FAILURE);
}

int processSPI(transferFrame* tf, securityAssociation* sa){
  // Check for tf and sa
  if (tf == NULL){
    printf("[ERROR] No transfer frame was provided\n");
    return -1;
  } else if (sa == NULL){
    printf("[ERROR] No security association was provided\n");
    return -1;
  }

  // Copy SPI to Security Header
  tf->sh->SPI = sa->SPI;
  return 0;
}

int processIV(transferFrame* tf, securityAssociation* sa, uint8_t useIVasSN){
  // Check for tf and sa
  if (tf == NULL){
    printf("[ERROR] No transfer frame was provided\n");
    return -1;
  } else if (sa == NULL){
    printf("[ERROR] No security association was provided\n");
    return -1;
  }

  // Define IV
  unsigned char* iv;
  // If we are using the IV as the SN
  if (useIVasSN == 1){
    // Allocate the IV
    iv = malloc(sa->SA_length_IV);
    if (iv == NULL){
      printf("[ERROR] Failed to allocate IV\n");
      return -1;
    }

    // Length of nonce
    size_t nonce_len = strlen(sa->SA_initialization_vector) - sa->SA_length_SN;

    // Copy nonce section and empty bytes for the SN section
    memcpy(iv, sa->SA_initialization_vector, nonce_len);
    memcpy(iv + nonce_len, &sa->SA_sequence_number, sa->SA_length_SN);
  // Otherwise, just use the SA's IV
  } else {
    iv = sa->SA_initialization_vector;
    if (iv == NULL){
      printf("[ERROR] No valid IV was able to be found\n");
      return -1;
    }
  }

  // Copy IV to Security Header
  tf->sh->IV = malloc(sa->SA_length_IV);
  if (tf->sh->IV == NULL){
    printf("[ERROR] Failed to allocate IV\n");
    return -1;
  }
  memcpy(tf->sh->IV, iv, sa->SA_length_IV);
  return 0;
}

int processSN(transferFrame* tf, securityAssociation* sa){
  // Check for tf and sa
  if (tf == NULL){
    printf("[ERROR] No transfer frame was provided\n");
    return -1;
  } else if (sa == NULL){
    printf("[ERROR] No security association was provided\n");
    return -1;
  }

  // Declare SN
  uint64_t sn = sa->SA_sequence_number;

  // Copy SN to Security Header
  tf->sh->SN = malloc(sa->SA_length_SN);
  if (tf->sh->SN == NULL){
    printf("[ERROR] Failed to allocate SN\n");
    return -1;
  }
  memcpy(tf->sh->SN, &sn, sa->SA_length_SN);

  // Check if rollover happened
  if (tf->sh->SN[0] == 0x00){
    printf("SN rollover detected\n");
  }
  return 0;
}

int processPL(transferFrame* tf, securityAssociation* sa, uint8_t pl){
  // Check for tf and sa
  if (tf == NULL){
    printf("[ERROR] No transfer frame was provided\n");
    return -1;
  } else if (sa == NULL){
    printf("[ERROR] No security association was provided\n");
    return -1;
  }

  // Copy PL to Security Header
  tf->sh->PL = malloc(sa->SA_length_PL);
  if (tf->sh->PL == NULL){
    printf("[ERROR] Failed to allocate PL\n");
    return -1;
  }
  memcpy(tf->sh->PL, &pl, sa->SA_length_PL);
  return 0;
}

uint64_t receiveSN(transferFrame* tf, securityAssociation* sa, uint8_t useIVasSN){
  // Check for tf and sa
  if (tf == NULL){
    printf("[ERROR] No transfer frame was provided\n");
    return 0;
  } else if (sa == NULL){
    printf("[ERROR] No security association was provided\n");
    return 0;
  }

  // Declare SN
  uint64_t sn;

  // If we are using the IV as the SN, copy the IV's section that contains the SN
  if (useIVasSN == 1){
    memcpy(&sn, tf->sh->IV + strlen(sa->SA_initialization_vector) - sa->SA_length_SN, sa->SA_length_SN);
  } else {
    // Otherwise, simply copy the SN field
    memcpy(&sn, tf->sh->SN, sa->SA_length_SN);
  }
  return sn;
}

int applyBitmask(unsigned char* auth_payload, size_t auth_len, securityAssociation* sa, int hasIV){
  // TODO: Switch indexes and handle the other TF fields of SPP 
  // Apply the bit mask in a bitwise-AND op
  for (size_t i = 0; i < auth_len; i++) {
    // If the auth_payload has an IV, & the bits corresponding to it with 0x00
    if (hasIV == 1 && i >= 2 && i < 2 + sa->SA_length_IV){
      auth_payload[i] = auth_payload[i] & sa->SA_authentication_mask;
      continue;
    }
  }
}

securityAssociation* FindSA(securityAssociation** sa_array, unsigned int sa_array_size, unsigned int GVCID, unsigned int GMAP_ID){
  // Check if the SA array exists
  if (sa_array == NULL){
    printf("[ERROR] No SA database was provided\n");
    return NULL;
  }

  // Iterate through the SA array to find the matching SA
  for (unsigned int i = 0; i < sa_array_size; i++) {
    // Make sure current isn't null
    if (sa_array[i] == NULL){
      continue;
    }

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
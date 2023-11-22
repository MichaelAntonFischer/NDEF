#include "Ntag424DNA.h"

Ntag424DNA::Ntag424DNA(PN532& nfcShield)
{
  _nfcShield = &nfcShield;
}

Ntag424DNA::~Ntag424DNA()
{
}

NfcTag Ntag424DNA::read(byte *uid, unsigned int uidLength)
{
    // Buffer to store the data read from the tag
    uint8_t data[256]; // Adjust size as needed

    // Authenticate with the tag
    if (!authenticate(uid, uidLength)) {
        // Handle authentication failure
        return NfcTag(uid, uidLength);
    }

    // Send the READ command to the tag
    _nfcShield->ntag2xx_ReadPage(uid, uidLength, data);

    // Create an NfcTag object with the data read from the tag
    return NfcTag(uid, uidLength, data);
}

boolean Ntag424DNA::write(NdefMessage& ndefMessage, byte *uid, unsigned int uidLength)
{
    // Buffer to store the NDEF message to be written to the tag
    uint8_t data[256]; // Adjust size as needed
    ndefMessage.getEncoded(data);

    // Authenticate with the tag
    if (!authenticate(uid, uidLength)) {
        // Handle authentication failure
        return false;
    }

    // Send the WRITE command to the tag
    return _nfcShield->ntag2xx_WritePage(uid, uidLength, data);
}

boolean Ntag424DNA::authenticate(byte *uid, unsigned int uidLength)
{
    // The static key
    byte staticKey[16] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

    // The key for AES-128 encryption
    byte key[16];

    // Reverse the UID and concatenate it with the static key to form the AES key
    for (int i = 0; i < uidLength; i++) {
        key[i] = uid[uidLength - 1 - i];
    }
    for (int i = uidLength; i < 16; i++) {
        key[i] = staticKey[i];
    }

    // The rest of the authenticate method...
}
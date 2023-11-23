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
    ndefMessage.getEncodedSize(data);

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

    // The command for the authentication
    byte command[] = {
        0x1A, // Command code for PWD_AUTH
    };

    // Append UID to the command
    for (int i = 0; i < uidLength; i++) {
        command[i + 1] = uid[i];
    }

    // Buffer to store the response from the tag
    byte response[20];

    // Send the command to the tag and get the response
    int responseLength = _nfcShield->inDataExchange(command, sizeof(command), response, sizeof(response));

    // Check the response length
    if (responseLength != 16) {
        return false;
    }

    // The first 2 bytes of the response are the status code
    // The remaining 14 bytes are the encrypted challenge
    byte status[2];
    byte encryptedChallenge[14];
    memcpy(status, response, 2);
    memcpy(encryptedChallenge, response + 2, 14);

    // Decrypt the challenge using the key
    AESLib aesLib;
    uint8_t decryptedChallenge[16]; // Ensure the size matches the encrypted data
    byte my_iv[16] = {0}; // Initialization vector, replace with actual value if needed
    aesLib.decrypt64((char*)encryptedChallenge, sizeof(encryptedChallenge), decryptedChallenge, key, 128, my_iv);

    // The decrypted challenge should match the original challenge
    // This verifies that the tag has the correct key
    if (memcmp(decryptedChallenge, command + 2, 14) != 0) {
        return false;
    }

    return true;
}
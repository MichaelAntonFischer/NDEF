#include <NfcAdapter.h>

NfcAdapter::NfcAdapter(PN532Interface &interface)
{
    shield = new PN532(interface);
}

NfcAdapter::~NfcAdapter(void)
{
    delete shield;
}

void NfcAdapter::begin(boolean verbose)
{
    shield->begin();

    uint32_t versiondata = shield->getFirmwareVersion();

    if (! versiondata)
    {
#ifdef NDEF_USE_SERIAL
        Serial.print(F("Didn't find PN53x board"));
#endif
        while (1); // halt
    }

    if (verbose)
    {
#ifdef NDEF_USE_SERIAL
        Serial.print(F("Found chip PN5")); Serial.println((versiondata>>24) & 0xFF, HEX);
        Serial.print(F("Firmware ver. ")); Serial.print((versiondata>>16) & 0xFF, DEC);
        Serial.print('.'); Serial.println((versiondata>>8) & 0xFF, DEC);
#endif
    }
    // configure board to read RFID tags
    shield->SAMConfig();
}

boolean NfcAdapter::tagPresent(unsigned long timeout)
{
    uint8_t success;
    uidLength = 0;

    if (timeout == 0)
    {
        success = shield->readPassiveTargetID(PN532_MIFARE_ISO14443A, uid, (uint8_t*)&uidLength);
    }
    else
    {
        success = shield->readPassiveTargetID(PN532_MIFARE_ISO14443A, uid, (uint8_t*)&uidLength, timeout);
    }
    return success;
}

boolean NfcAdapter::erase()
{
    NdefMessage message = NdefMessage();
    message.addEmptyRecord();
    return write(message);
}

boolean NfcAdapter::format()
{
    boolean success;
#ifdef NDEF_SUPPORT_MIFARE_CLASSIC
    if (uidLength == 4)
    {
        MifareClassic mifareClassic = MifareClassic(*shield);
        success = mifareClassic.formatNDEF(uid, uidLength);
    }
    else
#endif
    {
#ifdef NDEF_USE_SERIAL
        Serial.print(F("Unsupported Tag."));
#endif
        success = false;
    }
    return success;
}

boolean NfcAdapter::clean()
{
    uint8_t type = guessTagType();

#ifdef NDEF_SUPPORT_MIFARE_CLASSIC
    if (type == TAG_TYPE_MIFARE_CLASSIC)
    {
        #ifdef NDEF_DEBUG
        Serial.println(F("Cleaning Mifare Classic"));
        #endif
        MifareClassic mifareClassic = MifareClassic(*shield);
        return mifareClassic.formatMifare(uid, uidLength);
    }
    else
#endif
    if (type == TAG_TYPE_2)
    {
        #ifdef NDEF_DEBUG
        Serial.println(F("Cleaning Mifare Ultralight"));
        #endif
        MifareUltralight ultralight = MifareUltralight(*shield);
        return ultralight.clean();
    }
    else
    {
#ifdef NDEF_USE_SERIAL
        Serial.print(F("No driver for card type "));Serial.println(type);
#endif
        return false;
    }

}


NfcTag NfcAdapter::read()
{
    uint8_t type = guessTagType();

#ifdef NDEF_SUPPORT_MIFARE_CLASSIC
    if (type == TAG_TYPE_MIFARE_CLASSIC)
    {
        #ifdef NDEF_DEBUG
        Serial.println(F("Reading Mifare Classic"));
        #endif
        MifareClassic mifareClassic = MifareClassic(*shield);
        return mifareClassic.read(uid, uidLength);
    }
    else
#endif
    if (type == TAG_TYPE_2)
    {
        #ifdef NDEF_DEBUG
        Serial.println(F("Reading Mifare Ultralight"));
        #endif
        MifareUltralight ultralight = MifareUltralight(*shield);
        return ultralight.read(uid, uidLength);
    }
    else if (type == TAG_TYPE_UNKNOWN)
    {
#ifdef NDEF_USE_SERIAL
        Serial.print(F("Can not determine tag type"));
#endif
        return NfcTag(uid, uidLength);
    }
    else
    {
        // Serial.print(F("No driver for card type "));Serial.println(type);
        // TODO should set type here
        return NfcTag(uid, uidLength);
    }

}

boolean NfcAdapter::write(NdefMessage& ndefMessage)
{
    boolean success;
    uint8_t type = guessTagType();

#ifdef NDEF_SUPPORT_MIFARE_CLASSIC
    if (type == TAG_TYPE_MIFARE_CLASSIC)
    {
        #ifdef NDEF_DEBUG
        Serial.println(F("Writing Mifare Classic"));
        #endif
        MifareClassic mifareClassic = MifareClassic(*shield);
        success = mifareClassic.write(ndefMessage, uid, uidLength);
    }
    else
#endif
    if (type == TAG_TYPE_2)
    {
        #ifdef NDEF_DEBUG
        Serial.println(F("Writing Mifare Ultralight"));
        #endif
        MifareUltralight mifareUltralight = MifareUltralight(*shield);
        success = mifareUltralight.write(ndefMessage, uid, uidLength);
    }
    else if (type == TAG_TYPE_UNKNOWN)
    {
#ifdef NDEF_USE_SERIAL
        Serial.print(F("Can not determine tag type"));
#endif
        success = false;
    }
    else
    {
#ifdef NDEF_USE_SERIAL
        Serial.print(F("No driver for card type "));Serial.println(type);
#endif
        success = false;
    }

    return success;
}

boolean NfcAdapter::getATQAandSAK(byte *atqa, byte *sak)
{
    // Buffer to store the response from the tag
    byte response[20];
    byte responseLength;

    // Send the InListPassiveTarget command to the tag
    shield->inListPassiveTarget();

    // Get the response from the tag
    responseLength = shield->getCommandResponse(response);

    // Check the response length
    if (responseLength < 20) {
        return false;
    }

    // The ATQA is the first 2 bytes of the response
    atqa[0] = response[0];
    atqa[1] = response[1];

    // The SAK is the third byte of the response
    *sak = response[2];

    return true;
} 

unsigned int NfcAdapter::guessTagType()
{
    byte atqa[2];
    byte sak;
    // Get ATQA and SAK from the tag
    if (!getATQAandSAK(atqa, &sak)) {
        return TAG_TYPE_UNKNOWN;
    }

    // 4 byte id - Mifare Classic
    //  - ATQA 0x4 && SAK 0x8
    // 7 byte id
    //  - ATQA 0x44 && SAK 0x8 - Mifare Classic
    //  - ATQA 0x44 && SAK 0x0 - Mifare Ultralight NFC Forum Type 2
    //  - ATQA 0x344 && SAK 0x20 - NFC Forum Type 4
    //  - ATQA 0x424 && SAK 0x20 - NTAG424DNA

    if (uidLength == 4 && atqa[0] == 0x4 && sak == 0x8)
    {
        return TAG_TYPE_MIFARE_CLASSIC;
    }
    else if (uidLength == 7 && atqa[0] == 0x44 && sak == 0x8)
    {
        return TAG_TYPE_MIFARE_CLASSIC;
    }
    else if (uidLength == 7 && atqa[0] == 0x44 && sak == 0x0)
    {
        return TAG_TYPE_2;
    }
    else if (uidLength == 7 && atqa[0] == 0x344 && sak == 0x20)
    {
        return TAG_TYPE_4;
    }
    else if (uidLength == 7 && atqa[0] == 0x424 && sak == 0x20)
    {
        return TAG_TYPE_NTAG424DNA;
    }
    else
    {
        return TAG_TYPE_UNKNOWN;
    }
}

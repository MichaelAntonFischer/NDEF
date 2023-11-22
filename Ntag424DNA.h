#ifndef Ntag424DNA_h
#define Ntag424DNA_h

#include <PN532.h>
#include <Ndef.h>
#include <NfcTag.h>

class Ntag424DNA
{
    public:
        Ntag424DNA(PN532& nfcShield);
        ~Ntag424DNA();
        NfcTag read(byte *uid, unsigned int uidLength);
        boolean write(NdefMessage& ndefMessage, byte *uid, unsigned int uidLength);
        boolean Ntag424DNA::authenticate(byte *uid, unsigned int uidLength);
    private:
        PN532* _nfcShield;
};

#endif
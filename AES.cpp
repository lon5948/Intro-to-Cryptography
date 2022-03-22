#pragma comment(lib,"cryptlib.lib")

#include <iostream>
#include <fstream>
#include <string>
#include <cstdlib>
#include "cryptopp/cryptlib.h"
#include "cryptopp/hex.h"
#include "cryptopp/filters.h"
#include "cryptopp/aes.h"
#include "cryptopp/modes.h"

using namespace std;
using namespace CryptoPP;

ofstream out;

void printhex(string cipher) {
    string ans;

    StringSource ECB_ss2(cipher, true, new HexEncoder(new StringSink(ans)));

    out << ans << '\n';
}

void enc_cfb(const string plain, const byte key[], const byte iv[]) {
    string cipher;

    const AlgorithmParameters parameter = MakeParameters(Name::FeedbackSize(), 4)(Name::IV(), ConstByteArrayParameter(iv, 16));

    CFB_Mode<AES>::Encryption ecfb;
    ecfb.SetKey(key, 16, parameter);


    StringSource en(plain, true, new StreamTransformationFilter(ecfb, new StringSink(cipher)));

    printhex(cipher);
}

void enc_cbc(const string plain, const byte key[], const byte iv[], string padding) {
    string cipher;

    CBC_Mode<AES>::Encryption ecbc;
    ecbc.SetKeyWithIV(key, 16, iv);

    if (padding == "zero") {
        StringSource en(plain, true, new StreamTransformationFilter(ecbc, new StringSink(cipher), StreamTransformationFilter::ZEROS_PADDING));
    }
    else {
        StringSource en(plain, true, new StreamTransformationFilter(ecbc, new StringSink(cipher), StreamTransformationFilter::PKCS_PADDING));
    }

    printhex(cipher);
}

void enc_ecb(const string plain, const byte key[]) {
    string cipher;

    ECB_Mode<AES>::Encryption eecb;
    eecb.SetKey(key, 16);

    StringSource en(plain, true, new StreamTransformationFilter(eecb, new StringSink(cipher), StreamTransformationFilter::PKCS_PADDING));

    printhex(cipher);
}

int main() {

    out.open("out.txt");

    const byte key[17] = "1234567890ABCDEF";
    const string plain = "AES is the block cipher standard.";
    const byte iv1[17] = "0000000000000000";
    const byte iv2[17] = "9999999999999999";

    enc_cfb(plain, key, iv1);
    enc_cbc(plain, key, iv1, "zero");
    enc_cbc(plain, key, iv2, "pcks");
    enc_ecb(plain, key);

    out.close();

}

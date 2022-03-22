#pragma comment(lib,"cryptlib.lib")

#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <stdio.h>
#include "cryptopp/rsa.h"
#include "cryptopp/integer.h"
#include "cryptopp/osrng.h"
#include "cryptopp/pubkey.h"

using namespace CryptoPP;
using namespace std;

int main() {
	ofstream o;
	o.open("out.txt");

	// Encryption 1
	Integer n1("0x04823f9fe38141d93f1244be161b20f"), e1("0x11");

	RSA::PublicKey pukey1;
	pukey1.Initialize(n1,e1);

	int keylen1 = 128;

	Integer m1, c1;
	string message1 = "Hello World!";

	if (message1.size() * 8 <= keylen1) {
		m1 = Integer((const byte*)message1.data(), message1.size());
		c1 = pukey1.ApplyFunction(m1);
		string str1 = IntToString(c1, 16);
		//cout << hex << str1 << endl;
		o << hex << str1 << endl;
	}

	// Encryption 2
	Integer n2("0x9711ea5183d50d6a91114f1d7574cd52621b35499b4d3563ec95406a994099c9"), e2("0x10001");

	RSA::PublicKey pukey2;
	pukey2.Initialize(n2,e2);

	int keylen2 = 256;

	Integer m2, c2;
	string message2 = "RSA is public key.";

	if (message2.size() * 8 <= keylen2) {
		m2 = Integer((const byte*)message2.data(), message2.size());
		c2 = pukey2.ApplyFunction(m2);
		string str2 = IntToString(c2, 16);
		//cout << hex << str2 << endl;
		o << hex << str2 << endl;
	}

	//Decryption 

	Integer n3("253963006250652707627402859040685100389"), e3("65537"),d3("42772482296155483517134936268603049473");
	Integer c3("31639169974475525248366103533531939340");

	//int keylen3 = 128;
	int i = 10;

while (i>0) {

		try {
			RSA::PrivateKey prkey;
			prkey.Initialize(n3, e3, d3);
			AutoSeededRandomPool rng;
			Integer r = prkey.CalculateInverse(rng, c3);
			string str3 = IntToString(r, 10);
			int sum = 0;
			for (int j = 0; j < str3.length(); j++) {
				sum += int(str3[j])-'0';
			}
			if (sum%10==9) {
				cout << str3 << endl;
			}

			string pt;
			pt.resize(r.MinEncodedSize());
			r.Encode((byte*)pt.data(), pt.size());
			string str3 = IntToString(d3, 16);
			cout << str3 << endl;
			o << str3 << endl;
			for (int i = 0; i < pt.size(); i++) {
				cout << int(pt[i]) << " ";
			}
			cout << pt << endl;
			o << pt << endl;
			break;
		}
		catch(...){}

		c3++;
		i--;
	}
	return 0;
}

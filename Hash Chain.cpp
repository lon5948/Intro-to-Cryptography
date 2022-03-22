#pragma comment(lib,"cryptlib.lib")

#include <iostream>
#include <fstream>
#include <string>
#include <iomanip>
#include <stdio.h>
#include "cryptopp/cryptlib.h"
#include "cryptopp/sha.h"
#include "cryptopp/integer.h"
#include "cryptopp/hex.h"

using namespace CryptoPP;
using namespace std;

int main() {
	ofstream o;
	o.open("out.txt");

	string msg = "Hello!39";
	string str,digest,noncestr,newstr,m;
	bool flag= true;

	SHA256 hash;
	hash.Update((const byte*)msg.data(), msg.size());
	digest.resize(hash.DigestSize());
	hash.Final((byte*)&digest[0]);

	Integer dnum;
	dnum = Integer((const byte*)digest.data(), digest.size());
	str = IntToString(dnum, 2);
	cout << str;
	
	for (int zeronum = 0; zeronum < 10; zeronum++) {
		cout << zeronum << endl;
		for (long long i = 0; i < 0x100000000; i++) {
			Integer nonce = i;
			//cout << nonce << "   ";
			stringstream ss;
			noncestr = IntToString(nonce, 16);
			ss << setw(8) << setfill('0') << noncestr;
			ss >> noncestr;
			//cout << noncestr << endl;
			m = str + noncestr;
			//cout << m << endl;
			msg = "";
			StringSource strsource(m, true, new HexDecoder(new StringSink(msg)));
			SHA256 hash;
			hash.Update((const byte*)msg.data(), msg.size());
			digest.resize(hash.DigestSize());
			hash.Final((byte*)&digest[0]);

			Integer dnum;
			dnum = Integer((const byte*)digest.data(), digest.size());
			newstr = IntToString(dnum, 16);
			stringstream ssnew;
			ssnew << setw(64) << setfill('0') << newstr;
			ssnew >> newstr;
			//cout << newstr << endl;

			for (int i = 0; i < zeronum;i++) {
				if (newstr[i] != '0') {
					break;
				}
				else if (i == zeronum - 1 && newstr[i] == '0') {
					flag = true;
				}
			}

			if (flag == true) {
				o << zeronum << endl;
				o << str << endl;
				o << noncestr << endl;
				o << newstr << endl;

				str = newstr;
				flag = false;

				break;
			}

		}
	}
	
	
}

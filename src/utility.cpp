/*
 * Copyright (C) 2014 Mellnik
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <limits>

#include "cryptopp/base64.h"
#include "cryptopp/hex.h"
#include "cryptopp/sha.h"
#include "cryptopp/sha3.h"
#include "cryptopp/osrng.h"
#include "cryptopp/ripemd.h"
#include "cryptopp/whrlpool.h"
#include "cryptopp/pwdbased.h"
#include "cryptopp/filters.h"
#include "cryptopp/integer.h"

#include "utility.h"

void Utility::base64_encode(std::string input, std::string &output)
{
	CryptoPP::StringSource(input, true, new CryptoPP::Base64Encoder(new CryptoPP::StringSink(output), false));
}

void Utility::base64_decode(std::string input, std::string &output)
{
	CryptoPP::StringSource(input, true, new CryptoPP::Base64Decoder(new CryptoPP::StringSink(output)));
}

void Utility::hex_encode(std::string input, std::string &output)
{
	CryptoPP::StringSource(input, true, new CryptoPP::HexEncoder(new CryptoPP::StringSink(output)));
}

void Utility::hex_decode(std::string input, std::string &output)
{
	CryptoPP::StringSource(input, true, new CryptoPP::HexDecoder(new CryptoPP::StringSink(output)));
}

void Utility::sha256(std::string input, std::string &output)
{
	CryptoPP::SHA256 h_sha256;
	CryptoPP::StringSource(input, true, new CryptoPP::HashFilter(h_sha256, new CryptoPP::HexEncoder(new CryptoPP::StringSink(output))));
}

void Utility::sha384(std::string input, std::string &output)
{
	CryptoPP::SHA384 h_sha384;
	CryptoPP::StringSource(input, true, new CryptoPP::HashFilter(h_sha384, new CryptoPP::HexEncoder(new CryptoPP::StringSink(output))));
}

void Utility::sha512(std::string input, std::string &output)
{
	CryptoPP::SHA512 h_sha512;
	CryptoPP::StringSource(input, true, new CryptoPP::HashFilter(h_sha512, new CryptoPP::HexEncoder(new CryptoPP::StringSink(output))));
}

void Utility::sha3(std::string input, std::string &output)
{
	CryptoPP::SHA3_512 h_sha3;
	CryptoPP::StringSource(input, true, new CryptoPP::HashFilter(h_sha3, new CryptoPP::HexEncoder(new CryptoPP::StringSink(output))));
}

void Utility::whirlpool(std::string input, std::string &output)
{
	CryptoPP::Whirlpool h_Whirlpool;
	CryptoPP::StringSource(input, true, new CryptoPP::HashFilter(h_Whirlpool, new CryptoPP::HexEncoder(new CryptoPP::StringSink(output))));
}

void Utility::ripemd160(std::string input, std::string &output)
{
	CryptoPP::RIPEMD160 h_ripemd160;
	CryptoPP::StringSource(input, true, new CryptoPP::HashFilter(h_ripemd160, new CryptoPP::HexEncoder(new CryptoPP::StringSink(output))));
}

void Utility::ripemd256(std::string input, std::string &output)
{
	CryptoPP::RIPEMD256 h_ripemd256;
	CryptoPP::StringSource(input, true, new CryptoPP::HashFilter(h_ripemd256, new CryptoPP::HexEncoder(new CryptoPP::StringSink(output))));
}

void Utility::ripemd320(std::string input, std::string &output)
{
	CryptoPP::RIPEMD320 h_ripemd320;
	CryptoPP::StringSource(input, true, new CryptoPP::HashFilter(h_ripemd320, new CryptoPP::HexEncoder(new CryptoPP::StringSink(output))));
}

void Utility::random_string(std::string &random, unsigned length)
{
    CryptoPP::AutoSeededRandomPool RNG;
    CryptoPP::Integer rand_num(RNG, 32);

	for(unsigned i = 0; i < length; i++) 
	{
		unsigned num;

        if(!rand_num.IsConvertableToLong()) {
            num = std::numeric_limits<unsigned>::max() + static_cast<unsigned>(rand_num.AbsoluteValue().ConvertToLong());
        } else {
            num = static_cast<unsigned>(rand_num.AbsoluteValue().ConvertToLong());
        }

        num = num % 122;
        if(48 > num) {
			num += 48;
		}
        if(57 < num && 65 > num) {
            num += 7;
		}
        if(90 < num && 97 > num) {
            num += 6;
		}
        random += static_cast<char>(num);
        rand_num.Randomize(RNG, 32);
	}
}
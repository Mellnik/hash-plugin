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

#include <boost/chrono.hpp>
#include "cryptopp/hex.h"
#include "cryptopp/osrng.h"
#include "cryptopp/whrlpool.h"
#include "cryptopp/pwdbased.h"

#include "pbkdf2.h"

Pbkdf2::Pbkdf2(const char *key, unsigned iterations, CallbackData *cData) : 
	h_Key(key), h_Iterations(iterations)
{
	this->cData = cData;
	h_Worker = PBKDF2_GENERATE;
}

Pbkdf2::Pbkdf2(const char *key, const char *hash, const char *salt, unsigned iterations, CallbackData *cData) : 
	h_Key(key), h_Hash(hash), h_Salt(salt), h_Iterations(iterations)
{
	this->cData = cData;
	h_Worker = PBKDF2_VALIDATE;
	h_Equal = false;
}

Pbkdf2::~Pbkdf2()
{
	delete cData;
}

void Pbkdf2::Work()
{
	static const unsigned _PBKDF2_BYTE_ = 512 / 8;

	boost::chrono::steady_clock::time_point start = boost::chrono::steady_clock::now();
	
	CryptoPP::SecByteBlock byte_Derived(_PBKDF2_BYTE_);
	CryptoPP::PKCS5_PBKDF2_HMAC<CryptoPP::Whirlpool> pbkdf2;

	if(h_Worker == PBKDF2_GENERATE)
	{
		CryptoPP::SecByteBlock byte_Salt(_PBKDF2_BYTE_);
		CryptoPP::AutoSeededRandomPool RNG;
		RNG.GenerateBlock(byte_Salt, byte_Salt.size());
		CryptoPP::ArraySource(byte_Salt, byte_Salt.size(), true, new CryptoPP::HexEncoder(new CryptoPP::StringSink(h_Salt)));

		pbkdf2.DeriveKey(byte_Derived, byte_Derived.size(), 0x0, reinterpret_cast<const byte *>(h_Key.data()), h_Key.size(), reinterpret_cast<const byte *>(h_Salt.data()), h_Salt.size(), h_Iterations, 0);
		CryptoPP::ArraySource(byte_Derived, byte_Derived.size(), true, new CryptoPP::HexEncoder(new CryptoPP::StringSink(h_Hash)));
	}
	else if(h_Worker == PBKDF2_VALIDATE)
	{
		pbkdf2.DeriveKey(byte_Derived, byte_Derived.size(), 0x0, reinterpret_cast<const byte *>(h_Key.data()), h_Key.size(), reinterpret_cast<const byte *>(h_Salt.data()), h_Salt.size(), h_Iterations, 0);

		CryptoPP::SecByteBlock byte_Validate(_PBKDF2_BYTE_);
		CryptoPP::StringSource(h_Hash, true, new CryptoPP::HexDecoder(new CryptoPP::ArraySink(byte_Validate, byte_Validate.size())));

		// Length-constant comparison.
		unsigned diff = _PBKDF2_BYTE_ ^ _PBKDF2_BYTE_;
		for(unsigned i = 0; i < _PBKDF2_BYTE_; ++i)
		{
			diff |= byte_Derived[i] ^ byte_Validate[i];
		}
		h_Equal = diff == 0;
	}

	boost::chrono::steady_clock::duration duration = boost::chrono::steady_clock::now() - start;
	h_ExecTime = static_cast<unsigned>(boost::chrono::duration_cast<boost::chrono::milliseconds>(duration).count());
}
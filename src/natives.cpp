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

#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1 // for MD5 checksum

#include <fstream>

#include "cryptopp/base64.h"
#include "cryptopp/osrng.h"
#include "cryptopp/integer.h"
#include "cryptopp/files.h"
#include "cryptopp/hex.h"
#include "cryptopp/filters.h"
#include "cryptopp/md5.h" // for MD5 checksum
#include "cryptopp/sha.h"
#include "cryptopp/whrlpool.h"

#include "utility.h"
#include "pbkdf2.h"
#include "callback.h"
#include "natives.h"

cell AMX_NATIVE_CALL Native::hash_generate(AMX *amx, cell *params)
{
	static const unsigned ParameterCount = 4;

	if(params[0] < ParameterCount * sizeof(cell)) 
	{
		logprintf("[HASH] Invalid parameter count in hash_generate.");
		return 0;
	}

	if(params[2] < 1000) 
	{
		logprintf("[HASH] Invalid iteration count. Expected at least 1000.");
		return 0;
	}

	char *key = NULL, *callback = NULL, *format = NULL;
	amx_StrParam(amx, params[1], key);
	amx_StrParam(amx, params[3], callback);
	amx_StrParam(amx, params[4], format);

	if(key == NULL || callback == NULL || format == NULL) 
	{
		logprintf("[HASH] Failed to get hash_generate parameter.");
		return 0;
	}

	CallbackData *cData = new CallbackData;
	cData->Name = callback;

	Callback::Get()->Parameters(cData->Params, format, amx, params, ParameterCount);
	Callback::Get()->QueueWorker(new Pbkdf2(key, static_cast<unsigned>(params[2]), cData));
	return 1;
}

cell AMX_NATIVE_CALL Native::hash_retrieve(AMX *amx, cell *params)
{
	PARAM_CHECK(4, "hash_retrieve");

	if (Callback::Get()->GetActiveResult() == NULL)
	{
		logprintf("[HASH] No active result.");
		return 0;
	}

	if (Callback::Get()->GetActiveResult()->h_Worker != PBKDF2_GENERATE)
	{
		logprintf("[HASH] Invalid function call for hash validation.");
		return 0;
	}

	//Utility::amx_SetCString(amx, params[1], Callback::Get()->GetActiveResult()->h_Hash.c_str(), params[3]);
	//Utility::amx_SetCString(amx, params[2], Callback::Get()->GetActiveResult()->h_Salt.c_str(), params[4]);
	return 1;
}

cell AMX_NATIVE_CALL Native::hash_validate(AMX *amx, cell *params)
{
	static const unsigned ParameterCount = 6;

	if(params[0] < ParameterCount * sizeof(cell)) 
	{
		logprintf("[HASH] Invalid parameter count in hash_validate.");
		return 0;
	}

	if(params[4] < 1000) 
	{
		logprintf("[HASH] Invalid iteration count. Expected at least 1000.");
		return 0;
	}

	char *key = NULL, *callback = NULL, *format = NULL, *hash = NULL, *salt = NULL;
	amx_StrParam(amx, params[1], key);
	amx_StrParam(amx, params[2], hash);
	amx_StrParam(amx, params[3], salt);
	amx_StrParam(amx, params[5], callback);
	amx_StrParam(amx, params[6], format);

	if(key == NULL || callback == NULL || format == NULL || hash == NULL || salt == NULL) 
	{
		logprintf("[HASH] Failed to get hash_generate parameter.");
		return 0;
	}

	CallbackData *cData = new CallbackData;
	cData->Name = callback;

	Callback::Get()->Parameters(cData->Params, format, amx, params, ParameterCount);
	Callback::Get()->QueueWorker(new Pbkdf2(key, hash, salt, static_cast<unsigned int>(params[4]), cData));
	return 1;
}

cell AMX_NATIVE_CALL Native::hash_is_equal(AMX *amx, cell *params)
{
	if(Callback::Get()->GetActiveResult() != NULL) 
	{
		if(Callback::Get()->GetActiveResult()->h_Worker != PBKDF2_VALIDATE) 
		{
			logprintf("[HASH] Invalid function call for hash generation.");
			return 0;
		}
		else
		{
			return static_cast<cell>(Callback::Get()->GetActiveResult()->h_Equal);
		}
	}
	else
	{
		logprintf("[HASH] No active result.");
		return 0;
	}
}

cell AMX_NATIVE_CALL Native::hash_unprocessed(AMX *amx, cell *params)
{
	return static_cast<cell>(Callback::Get()->UnprocessedWorkerCount());
}

cell AMX_NATIVE_CALL Native::hash_exec_time(AMX *amx, cell *params)
{
	if(Callback::Get()->GetActiveResult() != NULL)
	{
		return static_cast<cell>(Callback::Get()->GetActiveResult()->h_ExecTime);
	}
	else
	{
		logprintf("[HASH] No active result.");
		return 0;
	}
}

cell AMX_NATIVE_CALL Native::hash_thread_limit(AMX *amx, cell *params)
{
	PARAM_CHECK(1, "hash_thread_limit");

	if(params[1] < 1) 
	{
		logprintf("[HASH] Invalid thread limit. Expected at least 1.");
		return 0;
	}
	
	Callback::Get()->SetThreadLimit(static_cast<unsigned int>(params[1]));
	return 1;
}

cell AMX_NATIVE_CALL Native::slow_equals(AMX *amx, cell *params)
{
	PARAM_CHECK(2, "slow_equals");

	char *a = NULL, *b = NULL;
	amx_StrParam(amx, params[1], a);
	amx_StrParam(amx, params[2], b);

	if(a == NULL || b == NULL) 
	{
		logprintf("[HASH] Failed to get slow_equals parameter.");
		return 0;
	}

	unsigned diff = strlen(a) ^ strlen(b);
	for(unsigned i = 0; i < strlen(a) && i < strlen(b); ++i)
		diff |= a[i] ^ b[i];
	
	return static_cast<cell>(diff == 0);
}

cell AMX_NATIVE_CALL Native::sha256(AMX *amx, cell *params)
{
	PARAM_CHECK(3, "sha256");
	
	char *str = NULL;
	amx_StrParam(amx, params[1], str);

	string hash;
	Utility::sha256(str, hash);
	Utility::amx_SetCString(amx, params[2], hash.c_str(), params[3]);
	return 1;
}

cell AMX_NATIVE_CALL Native::sha384(AMX *amx, cell *params)
{
	PARAM_CHECK(3, "sha384");
	
	char *str = NULL;
	amx_StrParam(amx, params[1], str);

	string hash;
	Utility::sha384(str, hash);
	Utility::amx_SetCString(amx, params[2], hash.c_str(), params[3]);
	return 1;
}

cell AMX_NATIVE_CALL Native::sha512(AMX *amx, cell *params)
{
	PARAM_CHECK(3, "sha512");
	
	char *str = NULL;
	amx_StrParam(amx, params[1], str);

	string hash;
	Utility::sha512(str, hash);
	Utility::amx_SetCString(amx, params[2], hash.c_str(), params[3]);
	return 1;
}

cell AMX_NATIVE_CALL Native::sha3(AMX *amx, cell *params)
{
	PARAM_CHECK(3, "sha3");
	
	char *str = NULL;
	amx_StrParam(amx, params[1], str);

	string hash;
	Utility::sha3(str, hash);
	Utility::amx_SetCString(amx, params[2], hash.c_str(), params[3]);
	return 1;
}

cell AMX_NATIVE_CALL Native::whirlpool(AMX *amx, cell *params)
{
	PARAM_CHECK(3, "whirlpool");
	
	char *str = NULL;
	amx_StrParam(amx, params[1], str);

	string hash;
	Utility::whirlpool(str, hash);
	Utility::amx_SetCString(amx, params[2], hash.c_str(), params[3]);
	return 1;
}

cell AMX_NATIVE_CALL Native::ripemd160(AMX *amx, cell *params)
{
	PARAM_CHECK(3, "ripemd160");
	
	char *str = NULL;
	amx_StrParam(amx, params[1], str);

	string hash;
	Utility::ripemd160(str, hash);
	Utility::amx_SetCString(amx, params[2], hash.c_str(), params[3]);
	return 1;
}

cell AMX_NATIVE_CALL Native::ripemd256(AMX *amx, cell *params)
{
	PARAM_CHECK(3, "ripemd256");
	
	char *str = NULL;
	amx_StrParam(amx, params[1], str);

	string hash;
	Utility::ripemd256(str, hash);
	Utility::amx_SetCString(amx, params[2], hash.c_str(), params[3]);
	return 1;
}

cell AMX_NATIVE_CALL Native::ripemd320(AMX *amx, cell *params)
{
	PARAM_CHECK(3, "ripemd320");
	
	char *str = NULL;
	amx_StrParam(amx, params[1], str);

	string hash;
	Utility::ripemd320(str, hash);
	Utility::amx_SetCString(amx, params[2], hash.c_str(), params[3]);
	return 1;
}

cell AMX_NATIVE_CALL Native::base64_encode(AMX *amx, cell *params)
{
	PARAM_CHECK(3, "base64_encode");

	char *str = NULL;
	amx_StrParam(amx, params[1], str);

	string base64;
	Utility::base64_encode(str, base64);
	Utility::amx_SetCString(amx, params[2], base64.c_str(), params[3]);
	return 1;
}

cell AMX_NATIVE_CALL Native::base64_decode(AMX *amx, cell *params)
{
	PARAM_CHECK(3, "base64_decode");

	char *str = NULL;
	amx_StrParam(amx, params[1], str);

	string decoded;
	Utility::base64_decode(str, decoded);
	Utility::amx_SetCString(amx, params[2], decoded.c_str(), params[3]);
	return 1;
}

cell AMX_NATIVE_CALL Native::hex_encode(AMX *amx, cell *params)
{
	PARAM_CHECK(3, "hex_encode");

	char *str = NULL;
	amx_StrParam(amx, params[1], str);

	string hex;
	Utility::hex_encode(str, hex);
	Utility::amx_SetCString(amx, params[2], hex.c_str(), params[3]);
	return 1;
}

cell AMX_NATIVE_CALL Native::hex_decode(AMX *amx, cell *params)
{
	PARAM_CHECK(3, "hex_decode");

	char *str = NULL;
	amx_StrParam(amx, params[1], str);

	string decoded;
	Utility::hex_decode(str, decoded);
	Utility::amx_SetCString(amx, params[2], decoded.c_str(), params[3]);
	return 1;
}

cell AMX_NATIVE_CALL Native::random_int(AMX *amx, cell *params)
{
	PARAM_CHECK(2, "random_int");

	if(params[2] < params[1] || params[2] == params[1]) // Prevent crash
	{
		logprintf("[HASH] Invalid input in random_int.");
		return 0;
	}

	CryptoPP::AutoSeededRandomPool RNG;
	CryptoPP::Integer num(RNG, 32);

	num.Randomize(RNG, params[1], params[2]);

	return static_cast<cell>(num.ConvertToLong());
}

cell AMX_NATIVE_CALL Native::random_string(AMX *amx, cell *params)
{
	PARAM_CHECK(3, "random_string");

	if(params[1] < 1) 
	{
		logprintf("[HASH] Invalid length specified.");
		return 0;
	}

	string random;
	Utility::random_string(random, static_cast<unsigned>(params[1]));
	Utility::amx_SetCString(amx, params[2], random.c_str(), params[3]);
	return 1;
}

cell AMX_NATIVE_CALL Native::md5sum(AMX *amx, cell *params)
{
	PARAM_CHECK(3, "md5sum");

	char *file = NULL;
	amx_StrParam(amx, params[1], file);

	if(file == NULL)
		return 0;

	if(!(std::ifstream(file))) 
	{
		logprintf("[HASH] File does not exist.");
		return 0;
	}

	string sum;
	CryptoPP::Weak::MD5 h_md5;
	CryptoPP::FileSource(file, true, new CryptoPP::HashFilter(h_md5, new CryptoPP::HexEncoder(new CryptoPP::StringSink(sum))));
	Utility::amx_SetCString(amx, params[2], sum.c_str(), params[3]);
	return 1;
}

cell AMX_NATIVE_CALL Native::sha1sum(AMX *amx, cell *params)
{
	PARAM_CHECK(3, "sha1sum");

	char *file = NULL;
	amx_StrParam(amx, params[1], file);

	if(file == NULL)
		return 0;

	if(!(std::ifstream(file))) 
	{
		logprintf("[HASH] File does not exist.");
		return 0;
	}

	string sum;
	CryptoPP::SHA1 h_sha1;
	CryptoPP::FileSource(file, true, new CryptoPP::HashFilter(h_sha1, new CryptoPP::HexEncoder(new CryptoPP::StringSink(sum))));
	Utility::amx_SetCString(amx, params[2], sum.c_str(), params[3]);
	return 1;
}

cell AMX_NATIVE_CALL Native::sha256sum(AMX *amx, cell *params)
{
	PARAM_CHECK(3, "sha256sum");

	char *file = NULL;
	amx_StrParam(amx, params[1], file);

	if(file == NULL)
		return 0;

	if(!(std::ifstream(file))) 
	{
		logprintf("[HASH] File does not exist.");
		return 0;
	}

	string sum;
	CryptoPP::SHA256 h_sha256;
	CryptoPP::FileSource(file, true, new CryptoPP::HashFilter(h_sha256, new CryptoPP::HexEncoder(new CryptoPP::StringSink(sum))));
	Utility::amx_SetCString(amx, params[2], sum.c_str(), params[3]);
	return 1;
}

cell AMX_NATIVE_CALL Native::sha384sum(AMX *amx, cell *params)
{
	PARAM_CHECK(3, "sha384sum");

	char *file = NULL;
	amx_StrParam(amx, params[1], file);

	if(file == NULL)
		return 0;

	if(!(std::ifstream(file))) 
	{
		logprintf("[HASH] File does not exist.");
		return 0;
	}

	string sum;
	CryptoPP::SHA384 h_sha384;
	CryptoPP::FileSource(file, true, new CryptoPP::HashFilter(h_sha384, new CryptoPP::HexEncoder(new CryptoPP::StringSink(sum))));
	Utility::amx_SetCString(amx, params[2], sum.c_str(), params[3]);
	return 1;
}

cell AMX_NATIVE_CALL Native::sha512sum(AMX *amx, cell *params)
{
	PARAM_CHECK(3, "sha512sum");

	char *file = NULL;
	amx_StrParam(amx, params[1], file);

	if(file == NULL)
		return 0;

	if(!(std::ifstream(file))) 
	{
		logprintf("[HASH] File does not exist.");
		return 0;
	}

	string sum;
	CryptoPP::SHA512 h_sha512;
	CryptoPP::FileSource(file, true, new CryptoPP::HashFilter(h_sha512, new CryptoPP::HexEncoder(new CryptoPP::StringSink(sum))));
	Utility::amx_SetCString(amx, params[2], sum.c_str(), params[3]);
	return 1;
}

cell AMX_NATIVE_CALL Native::wpsum(AMX *amx, cell *params)
{
	PARAM_CHECK(3, "wpsum");

	char *file = NULL;
	amx_StrParam(amx, params[1], file);

	if(file == NULL)
		return 0;

	if(!(std::ifstream(file))) 
	{
		logprintf("[HASH] File does not exist.");
		return 0;
	}

	string sum;
	CryptoPP::Whirlpool h_wp;
	CryptoPP::FileSource(file, true, new CryptoPP::HashFilter(h_wp, new CryptoPP::HexEncoder(new CryptoPP::StringSink(sum))));
	Utility::amx_SetCString(amx, params[2], sum.c_str(), params[3]);
	return 1;
}

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

#pragma once

#ifndef _UTILITY_H_
#define _UTILITY_H_


#include <string>
#include <stack>
#include <boost/variant.hpp>

using std::string;
using std::stack;
using boost::variant;

#include "main.h"


typedef struct
{
	string Name;
	stack< variant<cell, string> > Params;
} CallbackData;

namespace Utility
{
	void sha256(string input, string &output);
	void sha384(string input, string &output);
	void sha512(string input, string &output);
	void sha3(string input, string &output);
	void whirlpool(string input, string &output);
	void ripemd160(string input, string &output);
	void ripemd256(string input, string &output);
	void ripemd320(string input, string &output);
	void base64_encode(string input, string &output);
	void base64_decode(string input, string &output);
	void hex_encode(string input, string &output);
	void hex_decode(string input, string &output);
	void random_string(string &output, unsigned length);
	void amx_SetCString(AMX *amx, cell param, const char *str, int len);
};


#endif

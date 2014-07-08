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

#ifndef _PBKDF2_H_
#define _PBKDF2_H_

#include <string>

using std::string;

#include "utility.h"

enum E_PBKDF2_WORKER
{
	PBKDF2_GENERATE,
	PBKDF2_VALIDATE
};

class Pbkdf2 
{
public:
	Pbkdf2(const char *key, unsigned iterations, CallbackData *callback);
	Pbkdf2(const char *key, const char *hash, const char *salt, unsigned iterations, CallbackData *callback);
	~Pbkdf2();

	void Work();

	CallbackData *cData;
	E_PBKDF2_WORKER h_Worker;

	string h_Hash;
	string h_Salt;
	unsigned h_ExecTime;
	bool h_Equal;
private:
	unsigned h_Iterations;
	string h_Key;
};

#endif

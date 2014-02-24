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

#ifndef _NATIVES_H_
#define _NATIVES_H_

#include "main.h"

namespace Native
{
	// Hashing
	cell AMX_NATIVE_CALL sha256(AMX *amx, cell *params);
	cell AMX_NATIVE_CALL sha384(AMX *amx, cell *params);
	cell AMX_NATIVE_CALL sha512(AMX *amx, cell *params);
	cell AMX_NATIVE_CALL whirlpool(AMX *amx, cell *params);
	cell AMX_NATIVE_CALL ripemd160(AMX *amx, cell *params);
	cell AMX_NATIVE_CALL ripemd256(AMX *amx, cell *params);
	cell AMX_NATIVE_CALL ripemd320(AMX *amx, cell *params);

	// PBKDF2
	cell AMX_NATIVE_CALL hash_generate(AMX *amx, cell *params);
	cell AMX_NATIVE_CALL hash_retrieve(AMX *amx, cell *params);
	cell AMX_NATIVE_CALL hash_validate(AMX *amx, cell *params);
	cell AMX_NATIVE_CALL hash_is_equal(AMX *amx, cell *params);
	cell AMX_NATIVE_CALL hash_unprocessed(AMX *amx, cell *params);
	cell AMX_NATIVE_CALL hash_exec_time(AMX *amx, cell *params);
	cell AMX_NATIVE_CALL hash_thread_limit(AMX *amx, cell *params);

	// Non-cryptographic algorithms
	cell AMX_NATIVE_CALL base64_encode(AMX *amx, cell *params);
	cell AMX_NATIVE_CALL base64_decode(AMX *amx, cell *params);
	cell AMX_NATIVE_CALL hex_encode(AMX *amx, cell *params);
	cell AMX_NATIVE_CALL hex_decode(AMX *amx, cell *params);

	// Pseudo random generators
	cell AMX_NATIVE_CALL random_int(AMX *amx, cell *params);
	cell AMX_NATIVE_CALL random_string(AMX *amx, cell *params);

	// Checksums
	cell AMX_NATIVE_CALL md5sum(AMX *amx, cell *params);
	cell AMX_NATIVE_CALL sha1sum(AMX *amx, cell *params);
	cell AMX_NATIVE_CALL sha256sum(AMX *amx, cell *params);
	cell AMX_NATIVE_CALL sha384sum(AMX *amx, cell *params);
	cell AMX_NATIVE_CALL sha512sum(AMX *amx, cell *params);
	cell AMX_NATIVE_CALL wpsum(AMX *amx, cell *params);

	// Length-constant comparison
	cell AMX_NATIVE_CALL slow_equals(AMX *amx, cell *params);
};

#endif
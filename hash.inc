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

// Hash Plugin 0.0.3
 
#if defined _hash_included
	#endinput
#endif
#define _hash_included

#define PBKDF2_LENGTH 128
#define MD5_LENGTH 32
#define SHA1_LENGTH 40
#define SHA256_LENGTH 64
#define SHA384_LENGTH 96
#define SHA512_LENGTH 128
#define SHA3_LENGTH 128
#define WHIRLPOOL_LENGTH 128
#define RIPEMD160_LENGTH 40
#define RIPEMD256_LENGTH 64
#define RIPEMD320_LENGTH 80

// Hashing
native sha256(const key[], hash[], len = sizeof(hash));
native sha384(const key[], hash[], len = sizeof(hash)); 
native sha512(const key[], hash[], len = sizeof(hash));
native sha3(const key[], hash[], len = sizeof(hash));
native whirlpool(const key[], hash[], len = sizeof(hash));
native ripemd160(const key[], hash[], len = sizeof(hash));
native ripemd256(const key[], hash[], len = sizeof(hash));
native ripemd320(const key[], hash[], len = sizeof(hash));

// PBKDF2
native hash_generate(const key[], iterations, const callback[], const format[], {Float,_}:...);
native hash_retrieve(hash[], salt[], hlen = sizeof(hash), slen = sizeof(salt));
native hash_validate(const key[], const hash[], const salt[], iterations, const callback[], const format[], {Float,_}:...);
native hash_is_equal();
native hash_unprocessed();
native hash_exec_time();
native hash_thread_limit(threads);

// Non-cryptographic algorithms
native base64_encode(const input[], output[], len = sizeof(output));
native base64_decode(const input[], output[], len = sizeof(output));
native hex_encode(const input[], output[], len = sizeof(output));
native hex_decode(const input[], output[], len = sizeof(output));

// Pseudo random generators
native random_int(min, max);
native random_string(length, output[], len = sizeof(output));

// Checksums
native md5sum(const file[], sum[], len = sizeof(sum));
native sha1sum(const file[], sum[], len = sizeof(sum));
native sha256sum(const file[], sum[], len = sizeof(sum));
native sha384sum(const file[], sum[], len = sizeof(sum));
native sha512sum(const file[], sum[], len = sizeof(sum));
native wpsum(const file[], sum[], len = sizeof(sum));

// Length-constant comparison
native slow_equals(const a[], const b[]);
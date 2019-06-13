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

#ifndef _MAIN_H_
#define _MAIN_H_

#include <SDK/plugin.h>

#define PLUGIN_VERSION "0.0.5"
#define PARAM_CHECK(c, n) \
	if(params[0] != (c * 4)) \
	{ \
		logprintf("[HASH] Wrong paramenter(s) supplied in %s. Expected %i but found %i.", n, c, params[0] / 4); \
		return 0; \
	} \

typedef void (*logprintf_t)(const char*, ...);
extern logprintf_t logprintf;

#endif

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

#ifndef _PLUGIN_H_
#define _PLUGIN_H_

#include <list>

#include "main.h"

class Plugin
{
public:
	Plugin();
	~Plugin();

	void EraseAmx(AMX *amx);
	void AddAmx(AMX *amx);
	std::list<AMX *> &GetAmxList();

private:
	std::list<AMX *> amx_List;
};

extern Plugin *g_Plugin;

#endif
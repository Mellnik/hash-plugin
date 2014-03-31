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

#include "plugin.h"

Plugin *g_Plugin = NULL;

Plugin::Plugin()
{
	logprintf("[HASH] Plugin successfully loaded "PLUGIN_VERSION" (Compiled on "__DATE__", "__TIME__").");
}

Plugin::~Plugin()
{
	logprintf("[HASH] Plugin unloaded.");
}

void Plugin::AddAmx(AMX *amx)
{
	this->amx_List.push_back(amx);
}

void Plugin::EraseAmx(AMX *amx)
{
	for(std::list<AMX *>::iterator i = this->amx_List.begin(); i != this->amx_List.end(); ++i) 
	{
		if(*i == amx) 
		{
			this->amx_List.erase(i);
			break;
		}
	}
}

std::list<AMX *> &Plugin::GetAmxList()
{
	return this->amx_List;
}

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

#include "callback.h"
#include "plugin.h"


Callback::Callback() : 
	WorkerThreads(0)
{
	ThreadLimit = thread::hardware_concurrency() - 1 < 1 ? 3 : thread::hardware_concurrency() - 1;
}

void Callback::ProcessTick()
{
	lock_guard<mutex> lock(ResultMtx);

	Pbkdf2 *Queue = NULL;

	while (!pbkdf2_result.empty())
	{
		Queue = pbkdf2_result.front();

		list<AMX *> &AmxList = Plugin::Get()->GetAmxList();
		for (list<AMX *>::iterator i = AmxList.begin(); i != AmxList.end(); ++i)
		{
			int amx_Idx;

			if (amx_FindPublic(*i, Queue->cData->Name.c_str(), &amx_Idx) == AMX_ERR_NONE)
			{
				cell amx_Addr = -1;

				while (!Queue->cData->Params.empty())
				{
					variant<cell, string> Param(move(Queue->cData->Params.top()));

					if (auto v = std::get_if<cell>(&Param)) {
						amx_Push(*i, *v);
					}
					else if (auto v = std::get_if<string>(&Param)) {
						cell tmp;
						amx_PushString(*i, &tmp, NULL, (*v).c_str(), 0, 0);

						if (amx_Addr < 0)
							amx_Addr = tmp;
					}

					Queue->cData->Params.pop();
				}

				ActiveResult = Queue;

				cell amx_Ret;
				amx_Exec(*i, &amx_Ret, amx_Idx);
				if(amx_Addr >= 0) 
					amx_Release(*i, amx_Addr);

				ActiveResult = NULL;

				break;
			}
		}

		delete Queue;
		Queue = NULL;
	}
}

void Callback::ProcessTask()
{
	while (!pbkdf2_worker.empty())
	{
		if (WorkerThreads < ThreadLimit) 
		{
			WorkerThreads++;

			thread(&Callback::Worker, this, pbkdf2_worker.front()).detach();

			pbkdf2_worker.pop();
		}
		else {
			break;
		}
	}
}

void Callback::Parameters(stack< variant<cell, string> > &CallbackParameters, const char *format, AMX *amx, cell *params, const unsigned pcount)
{
	cell *amx_Ptr = NULL;
	char *str = NULL;

	for(unsigned i = 0, l = strlen(format); i < l; i++)
	{
		switch(format[i])
		{
		case 'i':
		case 'd':
		case 'b':
		case 'f':
			amx_GetAddr(amx, params[pcount + i + 1], &amx_Ptr);
			CallbackParameters.push(*amx_Ptr);
			break;
		case 's':
		case 'z':
			amx_StrParam(amx, params[pcount + i + 1], str);
			CallbackParameters.push(str == NULL ? string("") : string(str));
			str = NULL;
			break;
		default:
			CallbackParameters.push(string("NULL"));
		}
	}
}

queue<int>::size_type Callback::UnprocessedWorkerCount()
{
	return pbkdf2_worker.size();
}

void Callback::QueueWorker(Pbkdf2 *pbkdf2)
{
	pbkdf2_worker.push(pbkdf2);
}

void Callback::QueueResult(Pbkdf2 *pbkdf2)
{
	lock_guard<mutex> lock(ResultMtx);

	pbkdf2_result.push(pbkdf2);
	WorkerThreads--;
}

void Callback::Worker(Pbkdf2 *pbkdf2)
{
	pbkdf2->Work();

	QueueResult(pbkdf2);
}

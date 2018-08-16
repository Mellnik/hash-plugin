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

#ifndef _CALLBACK_H_
#define _CALLBACK_H_

#include <queue>
#include <stack>

using std::queue;
using std::stack;

#include <variant>
#include <thread>
#include <atomic>
#include <algorithm>
#include <mutex>
#include <utility>

using std::variant;
using std::thread;
using std::atomic;
using std::bind;
using std::mutex;
using std::lock_guard;
using std::move;

#include "pbkdf2.h"
#include "main.h"
#include "singleton.h"

class Callback : public CSingleton<Callback>
{
public:
	Callback();
	~Callback() { }

	void ProcessTick();
	void ProcessTask();
	void Parameters(stack< variant<cell, string> > &CallbackParameters, const char *format, AMX *amx, cell *params, const unsigned pcount);

	void QueueWorker(Pbkdf2 *pbkdf);
	void QueueResult(Pbkdf2 *pbkdf2);

	void Worker(Pbkdf2 *pbkdf2);

	queue<int>::size_type UnprocessedWorkerCount();

	Pbkdf2 *GetActiveResult()
	{
		return ActiveResult;
	}

	void SetThreadLimit(unsigned threads)
	{
		ThreadLimit = threads;
	}
private:
	queue<Pbkdf2 *> pbkdf2_worker;

	mutex ResultMtx;
	queue<Pbkdf2 *> pbkdf2_result;

	Pbkdf2 *ActiveResult;

	atomic<unsigned> ThreadLimit;
	atomic<unsigned> WorkerThreads;
};


#endif

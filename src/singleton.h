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

#ifndef _SINGLETON_H_
#define _SINGLETON_H_

#include <cstdlib>

template<class T>
class CSingleton
{
protected:
	static T *m_Instance;

public:
	virtual ~CSingleton() { }

	inline static T *Get()
	{
		if (m_Instance == NULL)
			m_Instance = new T;
		return m_Instance;
	}

	inline static void Destroy()
	{
		if (m_Instance != NULL)
		{
			delete m_Instance;
			m_Instance = NULL;
		}
	}
};

template <class T>
T* CSingleton<T>::m_Instance = NULL;

#endif // _SINGLETON_H_

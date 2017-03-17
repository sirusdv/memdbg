//#include "stdafx.h"




#include "MemoryDebugger.hpp"
#define _WIN32_WINNT 0x0700
#include <iostream> //workaround for a compiler bug that results in calls to new[] going to new
#include <fstream>
#include <map>
#define NOGDI 
#include <windows.h>
#include <DbgHelp.h>
#pragma comment (lib, "dbghelp.lib")

#ifdef _DEBUG
#define DEBUGON
#endif

#ifndef DEBUGON
#define _DEBUG
#endif

#include <assert.h>

#ifndef DEBUGON
#undef  _DEBUG
#endif





#ifndef ACCESSVIOLATIONS
#define ACCESSVIOLATIONS 0
#endif

#define TOTALSIZE (NOMANSIZE + m_Size + NOMANSIZE)
#define PAGESPAN  ((TOTALSIZE / PAGESIZE) + 1)

typedef std::map<size_t,Heap*,std::less<size_t> ,Mallocator<std::pair<size_t,Heap*> > > HEAPMAP;
#pragma warning ( disable : 4074 )
#pragma init_seg(compiler)
static CRITICAL_SECTION cs;
static HEAPMAP g_Heaps;
LONG WINAPI SEHHandler(EXCEPTION_POINTERS* pException)
{
	UNREFERENCED_PARAMETER(pException);

#if ACCESSVIOLATIONS != 0
	EXCEPTION_RECORD* walker = pException->ExceptionRecord;

	//get to original exception.
	while(walker->ExceptionRecord)
		walker = walker->ExceptionRecord;

	if(walker->ExceptionCode == EXCEPTION_ACCESS_VIOLATION)
	{
		for(HEAPMAP::iterator i=g_Heaps.begin();i!=g_Heaps.end();++i)
		{
			if(i->second->IsProtected((byte*)walker->ExceptionAddress))
			{
				_ASSERTE(0 && "BUFFER OVERFLOW / UNDERFLOW / WRITE AFTER DELETE DETECTED.");
			}
		}
	}
#endif
	return EXCEPTION_CONTINUE_SEARCH;
}

class SEHInit
{
public:
	SEHInit()
	{
		InitializeCriticalSection(&cs);
		SymInitialize(GetCurrentProcess(),NULL,true);
		SymSetOptions(SymGetOptions() | SYMOPT_LOAD_LINES);
		SetUnhandledExceptionFilter(SEHHandler);
	}
	~SEHInit()
	{
		for(HEAPMAP::iterator i=g_Heaps.begin();i!=g_Heaps.end();++i)
		{
			i->second->~Heap();
			free(i->second);
		}
		g_Heaps.clear();

		DeleteCriticalSection(&cs);

	}
};

static SEHInit SEH; 




extern "C" {

void* Alloc(size_t s, bool Vector = false)
{
	EnterCriticalSection(&cs);

	HEAPMAP::iterator itr = g_Heaps.find(s);
	if(itr == g_Heaps.end())
	{
		void* allocPtr = malloc(sizeof(Heap));
		_ASSERTE(allocPtr && "MALLOC FAILED!");
		Heap* pHeap = new (allocPtr) Heap(s);
		g_Heaps.insert(std::make_pair(s,pHeap));
	}

	void* val = g_Heaps.find(s)->second->Alloc(Vector);
	LeaveCriticalSection(&cs);
	return val;


}

void* Realloc(void *ptr, size_t size)
{
	EnterCriticalSection(&cs);
	void* ret = 0;
	for (HEAPMAP::iterator i=g_Heaps.begin();i!=g_Heaps.end();++i)
	{
		if(i->second->IsOwned((byte*)ptr))
		{
			HEAPMAP::iterator itr = g_Heaps.find(size);
			if(itr == g_Heaps.end())
			{
				Heap* pHeap = new (malloc(sizeof(Heap))) Heap(size);
				g_Heaps.insert(std::make_pair(size,pHeap));
			}

			ret = g_Heaps.find(size)->second->Alloc(false);

			memcpy(ret,ptr,i->first);
			break;
			}
		}//for
		if (ret == 0)
			{
				_ASSERTE(0 && "POINTER NOT OWNED BY MEMORY MANAGER.");
			}

	LeaveCriticalSection(&cs);
	return ret;
}

void Delete(void *ptr,bool Vector = false)
{
	if(!ptr)
		return;

	EnterCriticalSection(&cs);

	for (HEAPMAP::iterator i=g_Heaps.begin();i!=g_Heaps.end();++i)
	{
		if(i->second->IsOwned((byte*)ptr))
		{
			i->second->Delete(ptr,Vector);
			LeaveCriticalSection(&cs);
			return;
		}
	}
	LeaveCriticalSection(&cs);
	_ASSERTE(0 && "POINTER NOT OWNED BY MEMORY MANAGER.");
}

}
void FlushPages()
{
	return;
EnterCriticalSection(&cs);

	for (HEAPMAP::iterator i=g_Heaps.begin();i!=g_Heaps.end();++i)
	{
//		i->second->Flush();
	}

LeaveCriticalSection(&cs);
}

#pragma warning(push)
#pragma warning(disable: 4290)
void * operator new(size_t size) throw (std::bad_alloc) {return Alloc(size);}
void * operator new(size_t size, const std::nothrow_t&) throw () {return Alloc(size);}
void * operator new[](size_t size) throw (std::bad_alloc) {return Alloc(size,true);}
void * operator new[](size_t size, const std::nothrow_t&) throw () {return Alloc(size,true);}
void operator delete(void * ptr) throw () {Delete(ptr);}
void operator delete(void * ptr, const std::nothrow_t&) throw () {Delete(ptr);}
void operator delete[](void * ptr) throw () {Delete(ptr,true);}
void operator delete[](void * ptr, const std::nothrow_t&) throw () {Delete(ptr,true);}
#pragma warning(pop)

void debugprintf(const char *str,...)
{
	va_list mkr;
	char buff[2048];

	va_start(mkr,str);
	vsprintf_s(buff,_countof(buff),str,mkr);
	va_end(mkr);

	OutputDebugStringA(buff);
	std::fstream out("leaks.log",std::ios::app | std::ios::out);
	out << buff;
	out.flush();
	out.close();

}
void PrintLeak(unsigned __int64 addr, size_t size)
{
	IMAGEHLP_LINE64 hlp = {0};

	char* file = "Unknown";
	unsigned line = 0;
	DWORD symbol_offset = 0;



	if(SymGetLineFromAddr64(GetCurrentProcess(),addr,&symbol_offset,&hlp))
	{
		file = hlp.FileName;
		line = hlp.LineNumber;	
	}

	
	printf("%s(%u): Leak Detected (%u bytes).\r\n",file,line,size);			
}

/*size_t Heap::GetSize() const
{
	return m_Size;
}*/
Heap::Heap(size_t size)
: m_Size(size)
{

}
Heap::~Heap()
{
	for(HLEVECTOR::iterator i=m_Free.begin();i!= m_Free.end();++i)
	{
		if(!Validate(&(*i)))
		{
			_ASSERTE(0 && "WRITE AFTER DELETE DETECTED! Turn on ACCESSVIOLATIONS to break imediately!");
		}
	}
	for(HLEVECTOR::iterator i=m_Distributed.begin();i!= m_Distributed.end();++i)
	{
		
		if(!Validate(&(*i)))
		{
			_ASSERTE(0 && "BUFFER OVERFLOW / UNDERFLOW DETECTED! Turn on ACCESSVIOLATIONS to break immediately!");
		}

#if PRINTLEAKS == 1
		PrintLeak(i->AllocatingAddress,m_Size);
#endif
	}

	for(VOIDVECTOR::iterator i=m_SystemAllocated.begin();i!=m_SystemAllocated.end();++i)
	{
#if ACCESSVIOLATIONS == 0
		free(*i);
#else
		VirtualFree(*i,0,MEM_RELEASE);
#endif
	}
}

void* Heap::Alloc(bool Vector, unsigned stacklookup /* = 5 */)
{
	HeapListEntry hle = GetAvailable();
	if(hle.Data)
	{
		Protect(&hle,PL_PARTIAL);
		hle.AllocatingAddress = GetCallingFunction(stacklookup);
		hle.Type = Vector?HLAT_VECTOR:HLAT_SINGLE;
		m_Distributed.push_back(hle);
	}
	return hle.Data;
}
void Heap::Delete(void* ptr,bool Vector)
{

	if(IsInList(&m_Free,(const byte*)ptr))
	{
		_ASSERTE(0 && "DOUBLE DELETE DETECTED");
	}
	else if(IsInList(&m_Distributed,(const byte*)ptr))
	{
		HeapListEntry* pEntry;
		FindHLE(ptr,NULL,&pEntry);
		if(pEntry->Type != (Vector?HLAT_VECTOR:HLAT_SINGLE))
		{
			_ASSERTE(0 && "delete/delete[] missmatch");
		}

		if(!Validate(pEntry))
		{
			_ASSERTE(0 && "BUFFER OVERFLOW / UNDERFLOW DETECTED! Turn on ACCESSVIOLATIONS to break immediately!");
		}

		HeapListEntry entry;
		for(HLEVECTOR::iterator i = m_Distributed.begin();i!=m_Distributed.end();++i)
			if(i->Data == pEntry->Data)
			{
				entry = *i;
				m_Distributed.erase(i);
				break;
			}

			memset(entry.Data,FREED,m_Size);
			Protect(&entry,PL_FULL);
			m_Free.push_back(entry);
	}
	else
	{
		_ASSERTE(0 && "ATTEMPTING TO DELETE UNOWNED POINTER.");
	}

}
bool Heap::IsOwned(const void* ptr) const
{
	return IsInList(&m_Distributed,(const byte*)ptr) || IsInList(&m_Free,(const byte*)ptr);
}
bool Heap::IsProtected(const void* ptr) const
{
	HeapListEntry* hle = NULL;
	
	if(!hle) FindInList(&m_Distributed,ptr);
	if(!hle) FindInList(&m_Free,ptr);

	if(hle)
	{
		ProtectedRegion pr = GetProtectedRegion(hle);
		if((byte*)ptr >= pr.base && (unsigned)((byte*)ptr - pr.base) < pr.len)
			return true;

	}

	return false;
}
HeapListEntry Heap::GetAvailable()
{
	HeapListEntry hle;
	hle.Data = NULL;

	if(GetFromVector(&m_Free,&hle))
		return hle;
	if(GetFromVector(&m_Allocated,&hle))
		return hle;

	Grow();
	GetFromVector(&m_Allocated,&hle);
	return hle;
}
bool Heap::GetFromVector(HLEVECTOR* v, HeapListEntry* pOut)
{
	if(!v || !pOut || v->empty())
		return false;

	*pOut = v->back();
	v->pop_back();

	return true;
}

unsigned __int64 Heap::GetCallingFunction(unsigned depth)
{
	CONTEXT c;
#ifdef _WIN64
	RtlCaptureContext(&c);
	STACKFRAME64 stack_frame = {0};
	stack_frame.AddrPC.Mode = AddrModeFlat;
	stack_frame.AddrPC.Offset = c.Rip;
	stack_frame.AddrStack.Mode = AddrModeFlat;
	stack_frame.AddrStack.Offset = c.Rsp;
	stack_frame.AddrFrame.Mode = AddrModeFlat;
	stack_frame.AddrFrame.Offset = c.Rbp;
#else
	c.ContextFlags = CONTEXT_CONTROL;
	__asm
	{
LABEL: mov eax, [LABEL];
		mov c.Eip, eax;
		mov c.Ebp, ebp;
		mov c.Esp, esp;
	}
	STACKFRAME64 stack_frame = {0};
	stack_frame.AddrPC.Mode = AddrModeFlat;
	stack_frame.AddrPC.Offset = c.Eip;
	stack_frame.AddrStack.Mode = AddrModeFlat;
	stack_frame.AddrStack.Offset = c.Esp;
	stack_frame.AddrFrame.Mode = AddrModeFlat;
	stack_frame.AddrFrame.Offset = c.Ebp;
#endif
	

	for(unsigned i=0;i<depth;++i)
		StackWalk64(IMAGE_FILE_MACHINE_I386,GetCurrentProcess(),GetCurrentThread(),&stack_frame,&c,NULL,SymFunctionTableAccess64,SymGetModuleBase64,NULL);


	return stack_frame.AddrPC.Offset;

}

void Heap::Grow()
{

#if ACCESSVIOLATIONS == 0
		byte* ptr = (byte*)malloc(TOTALSIZE);
		//byte* ptrend = ptr + TOTALSIZE;
#else
	size_t allocsize = std::max<size_t>(0x10000,(PAGESPAN+1)*PAGESIZE);
		byte* ptr = (byte*)VirtualAlloc(NULL,allocsize,MEM_COMMIT,PAGE_READWRITE);
		byte* ptrend = ptr + allocsize;
#endif	

		_ASSERTE(ptr && "COULD NOT ALLOCATE MORE MEMORY");

		if(ptr)
		{
			m_SystemAllocated.push_back(ptr);
#if ACCESSVIOLATIONS == 0
			// dont need to do anything
			{
#else
	while(ptr+(PAGESPAN+1)*PAGESIZE <= ptrend)
	{
#endif
	byte* ptrbase = ptr;
#if ACCESSVIOLATIONS == 1
			ptr += (PAGESPAN)*PAGESIZE;
			ptr -= m_Size + NOMANSIZE;
#endif
#if ACCESSVIOLATIONS == 2
			ptr += PAGESIZE - NOMANSIZE;
#endif
			memset(ptr,NOMAND,NOMANSIZE);
			memset(ptr+NOMANSIZE,ALLOCD,m_Size);
			memset(ptr+NOMANSIZE+m_Size,NOMAND,NOMANSIZE);
			HeapListEntry hle;
			hle.Data = ptr+NOMANSIZE;
			Protect(&hle,PL_PARTIAL);
			m_Allocated.push_back(hle);

			ptr = ptrbase + (PAGESPAN+1)*PAGESIZE;
			}
		}
	
}
void Heap::Protect(HeapListEntry* hle, ProtectionLevel level)
{
	hle->Protection = level;
#if ACCESSVIOLATIONS == 0
	return;
#else
	DWORD protlevel;
	void* start = NULL;
	size_t size;

	switch(level)
	{
	case PL_NONE:
		protlevel = PAGE_READWRITE;
		start = hle->Data - NOMANSIZE;
		size = TOTALSIZE;
		break;
	case PL_PARTIAL:
		{
			Protect(hle,PL_NONE);
			ProtectedRegion pr = GetProtectedRegion(hle);
			protlevel = PAGE_NOACCESS;
			start = pr.base;
			size = pr.len;
			break;
		}
	case PL_FULL:
		protlevel = PAGE_NOACCESS;
		start = hle->Data - NOMANSIZE;
		size = TOTALSIZE;
		break;
	}

	DWORD oldProt = 0;
	if(!VirtualProtect(start,size,protlevel,&oldProt))
	{
		_ASSERTE(0 && "FAILED TO PROTECT PAGE.");
	}
#endif
}
Heap::ProtectedRegion Heap::GetProtectedRegion(const HeapListEntry* hle) const
{
	ProtectedRegion ret(NULL,0);
#if ACCESSVIOLATIONS == 0
	ret.base = hle->Data;
	ret.len = 0;
#endif
#if ACCESSVIOLATIONS == 1
	ret.base = hle->Data + m_Size ;
	ret.len = 1;	
#endif
#if ACCESSVIOLATIONS == 2
	ret.base = hle->Data - 1;
	ret.len = 1;
#endif
	return ret;
}
bool Heap::IsInList(const HLEVECTOR* vec,const HeapListEntry* entry) const
{
	return IsInList(vec,entry->Data);
}
bool Heap::IsInList(const HLEVECTOR* vec,const byte* ptr) const
{
	for(HLEVECTOR::const_iterator i=vec->begin();i!=vec->end();++i)
		if(i->Data == ptr)
			return true;
	return false;
}

const HeapListEntry* Heap::FindInList(const HLEVECTOR* list,const void* ptrData) const
{
	for(HLEVECTOR::const_iterator i=list->begin();i!= list->end();++i)
		if(i->Data == ptrData)
			return &(*i);

	return NULL;
}
HeapListEntry* Heap::FindInList(HLEVECTOR* list,const void* ptrData) const
{
	for(HLEVECTOR::iterator i=list->begin();i!= list->end();++i)
		if(i->Data == ptrData)
			return &(*i);

	return NULL;
}
bool Heap::FindHLE(const void* ptrData, HLEVECTOR** oList, HeapListEntry** oHLE)
{
	HeapListEntry* ret = NULL;

	if(ret = FindInList(&m_Distributed,ptrData))
	{
		if(oList) *oList = &m_Distributed;
		if(oHLE) *oHLE = ret;
		return true;
	}
	else if(ret = FindInList(&m_Free,ptrData))
	{
		if(oList) *oList = &m_Free;
		if(oHLE) *oHLE = ret;
		return true;
	}
	return false;
}
bool Heap::Validate(HeapListEntry* hle)
{
	ProtectionLevel old = hle->Protection;
	bool ret = false;
	Protect(hle,PL_NONE);

	if(IsInList(&m_Free,hle))
	{
		ret = IsCorrectPattern(hle->Data - NOMANSIZE,NOMANSIZE,NOMAND) &&
			IsCorrectPattern(hle->Data,m_Size,FREED) &&
			IsCorrectPattern(hle->Data + m_Size,NOMANSIZE,NOMAND);
	}
	else if(IsInList(&m_Distributed,hle))
	{
		ret = IsCorrectPattern(hle->Data - NOMANSIZE,NOMANSIZE,NOMAND) &&
			IsCorrectPattern(hle->Data + m_Size,NOMANSIZE,NOMAND);		
	}

	Protect(hle,old);
	return ret;
}
bool Heap::IsCorrectPattern(const byte* ptr,size_t size, byte pat) const
{
	for(unsigned i=0;i<size;++i)
		if(ptr[i] != pat)
			return false;
	return true;
}
void Heap::PrintDetails(const HeapListEntry* hle, const char * details) const
{
	char* file = "Unknown";
	unsigned line = 0;

	IMAGEHLP_LINE64 hlp = {0};
	DWORD symbol_offset = 0;
	if(SymGetLineFromAddr64(GetCurrentProcess(),hle->AllocatingAddress,&symbol_offset,&hlp))
	{
		file = hlp.FileName;
		line = hlp.LineNumber;	
	}

	debugprintf("%s(%u): %s  (%u bytes).\r\n",file,line,details,m_Size);
}
void Heap::Flush()
{

}


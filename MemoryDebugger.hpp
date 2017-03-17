#pragma once
#define ACCESSVIOLATIONS 0 //0 off, 1 overflow, 2 underflow
#define PRINTLEAKS 1
#define PAGESIZE 0x1000
#define ALLOCD 0xA0
#define FREED 0xFD
#define NOMAND 0xFE
#define NOMANSIZE 0x10

#include "mallocator.hpp"
#include <vector>
typedef unsigned char byte;


enum HeapListAllocType : byte
{
	HLAT_VECTOR,
	HLAT_SINGLE
};
enum ProtectionLevel: byte
{
	PL_NONE,
	PL_PARTIAL,
	PL_FULL
};

struct HeapListEntry
{
	HeapListAllocType Type;
	ProtectionLevel Protection;
	unsigned __int64 AllocatingAddress;
	byte* Data;
};

class Heap
{
public:
	Heap(size_t size);
	~Heap();
	void* Alloc(bool Vector, unsigned stacklookup = 5);
	void Delete(void* ptr,bool Vector);
	bool IsOwned(const void* ptr) const;
	bool IsProtected(const void* ptr) const;
//	size_t GetSize() const;
private:
	struct ProtectedRegion
	{
		byte* base;
		size_t len;
		ProtectedRegion(byte* b, size_t l)
			: base(b), len(l)
		{
		}
	};
	typedef std::vector<ProtectedRegion,Mallocator<ProtectedRegion> >  PRVECTOR;
	typedef std::vector<void*,Mallocator<void*> > VOIDVECTOR;
	typedef std::vector<HeapListEntry,Mallocator<HeapListEntry> > HLEVECTOR;
	
	size_t m_Size;
	VOIDVECTOR m_SystemAllocated;
	HLEVECTOR m_Free,m_Allocated,m_Distributed;

	HeapListEntry GetAvailable();
	bool GetFromVector(HLEVECTOR* v, HeapListEntry* pOut);

	unsigned __int64 GetCallingFunction(unsigned depth);
	
	void Grow();
	void Flush();
	void Protect(HeapListEntry* hle, ProtectionLevel level);
	ProtectedRegion GetProtectedRegion(const HeapListEntry* hle) const;
	bool IsCorrectPattern(const byte*ptr,size_t size, byte pat) const;
	
	bool IsInList(const HLEVECTOR* vec,const HeapListEntry* entry) const;
	bool IsInList(const HLEVECTOR* vec,const byte* ptr) const;
	
	const HeapListEntry* FindInList(const HLEVECTOR* list,const void* ptrData) const;
	HeapListEntry* FindInList(HLEVECTOR* list, const void* ptrData) const;
	bool FindHLE(const void* ptrData, HLEVECTOR** oList,HeapListEntry** oHLE);

	bool Validate(HeapListEntry* hle);
	void PrintDetails(const HeapListEntry* hle, const char * details) const;


	
	
};
#pragma once
#include <limits>
#include <cstdlib>

// This is taken from the example in the book
// "The C++ Standard Library"
//     - I highly recommend this book
// This presentation is also very helpful
// "Custom STL Allocators" by Pete Isensee
// http://www.tantalon.com/pete/customallocators.ppt

template <class T>
class Mallocator {
public:
	// Type Definitions
	typedef T value_type;
	typedef T* pointer;
	typedef const T* const_pointer;
	typedef T& reference;
	typedef const T& const_reference;
	typedef std::size_t size_type;
	typedef std::ptrdiff_t difference_type;

	// Rebind Allocator to Type U
	// Used for obtaining an allocator of a different type
	// For example std::list<int, Mallocator<int> > l;
	// std::list needs to allocate linked list nodes!
	template <class U> struct rebind {
		typedef Mallocator<U> other;
	};

	// Return Address of a Value
	pointer address(reference value) const {
		return &value;
	}

	const_pointer address(const_reference value) const {
		return &value;
	}

	// CTOR and DTOR.  These do nothing for this simple allocator
	Mallocator() { }
	~Mallocator() { }
	Mallocator(const Mallocator&) { }
	Mallocator& operator=(const Mallocator&) { return *this; }
	template <class U> Mallocator(const Mallocator<U>&) { }

	// This returns the maximum number of ELEMENTS that can be allocated
	size_type max_size() const {
		return std::numeric_limits<std::size_t>::max() / sizeof(T);
	}

	// This allocates the memory for num elements of type T
	pointer allocate(size_type num) {
		if (num == 0) { return NULL; }

		if (num > max_size()) {
			// Too many elements
			// This check is to prevent the overflow:
			//    BIG * BIG = SMALL
			//    malloc(SMALL) will succeed
			throw std::length_error("Mallocator Too Many Elements");
		}

		void* ptr = malloc(num * sizeof(T));

		if (!ptr) {
			// malloc failed
			throw std::bad_alloc();
		}

		return static_cast<pointer>(ptr);
	}

	pointer allocate(const size_t n, const void* /* unused */) {
		return allocate(n);
	}

	// And this deallocates the memory
	void deallocate(pointer p, size_type /* num */) {
		free(p);
	}

	// Call the constructor with placement new
	void construct(pointer p, const T& value) {
		new(static_cast<void*>(p)) T(value);
	}

	// Call the destructor
	void destroy(pointer p) {
		p->~T();
		(void)p;
	}
};

template <class T1, class T2>
bool operator==(const Mallocator<T1>&, const Mallocator<T2>&) {
	return true;
}

template <class T1, class T2>
bool operator!= (const Mallocator<T1>&, const Mallocator<T2>&) {
	return false;
}

#include "DataAlign_Hash.h"
#include "FeatureHeader.h"
#include <stdlib.h>


#define FORCE_INLINE	__forceinline
#define ROTL32(x,y)	_rotl(x,y)
#define ROTL64(x,y)	_rotl64(x,y)
#define BIG_CONSTANT(x) (x)
#pragma warning(disable:4146)


FORCE_INLINE uint32_t getblock(const uint32_t* p, size_t i)
{
	return p[i];
}


__declspec(noinline)  uint32_t fmix(uint32_t h) {
	h ^= h >> 16;
	h *= 0x85ebca6b;
	h ^= h >> 13;
	h *= 0xc2b2ae35;
	h ^= h >> 16;

	return h;
}


__declspec(noinline)  void MurmurHash3_x86_32(const void* key, size_t len, uint32_t seed,
	void* out) {
	const uint8_t* data = (const uint8_t*)key;
	size_t nblocks = len / 4;

	//printf("MurmurHash3_x86_32 \n\n len ==> %d Data ==> %s count ==> %d\n", len, data, nblocks);
	uint32_t h1 = seed;

	uint32_t c1 = 0xcc9e2d51;
	uint32_t c2 = 0x1b873593;

	//----------
	// body

	const uint32_t* blocks = (const uint32_t*)(data + nblocks * 4);


	for (size_t i = -nblocks; i; i++) {
		uint32_t k1 = getblock(blocks, i);

		k1 *= c1;
		k1 = ROTL32(k1, 15);
		k1 *= c2;
		//printf("K1 = %x\n", k1);

		h1 ^= k1;
		h1 = ROTL32(h1, 13);
		h1 = h1 * 5 + 0xe6546b64;
	}



	const uint8_t* tail = (const uint8_t*)(data + nblocks * 4);

	uint32_t k1 = 0;

	switch (len & 3) {
	case 3:
		k1 ^= tail[2] << 16;
	case 2:
		k1 ^= tail[1] << 8;
	case 1:
		k1 ^= tail[0];
		k1 *= c1;
		k1 = ROTL32(k1, 15);
		k1 *= c2;
		h1 ^= k1;
	};



	h1 ^= len;

	h1 = fmix(h1);

	*(uint32_t*)out = h1;
}


__declspec(noinline)  void featureHasher(struct FeatNode* featureMap, int numFeatures,
	float* featureArray) {
	struct FeatNode* last = featureMap;
	while (last != NULL) {

		char* key = last->key;
		size_t len = strlen(last->key);
		uint32_t seed = 0;
		int out;
		MurmurHash3_x86_32(key, len, seed, &out);
		int index;
		if (out == -2147483648) {
			index = (2147483647 - (numFeatures - 1)) % numFeatures;
		}
		else {
			index = abs(out) % numFeatures;
		}
		if (out >= 0) {
			featureArray[index] = featureArray[index] + (last->value);
		}
		else {
			featureArray[index] = featureArray[index] + ((last->value) * (-1));
		}
		last = last->next;
	}

}


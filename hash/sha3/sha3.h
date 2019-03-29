#ifndef SHA3_H
#define SHA3_H

#define SHA3_KECCAK_SPONGE_WORDS \
	(((1600)/8)/sizeof(uint64_t))
typedef struct sha3_context_ {
    uint64_t saved;            
    union {                 
        uint64_t s[SHA3_KECCAK_SPONGE_WORDS];
        uint8_t sb[SHA3_KECCAK_SPONGE_WORDS * 8];
    };
    unsigned byteIndex;         
    unsigned wordIndex;         
    unsigned capacityWords;     
} sha3_context;

enum SHA3_FLAGS {
    SHA3_FLAGS_NONE=0,
    SHA3_FLAGS_KECCAK=1
};

enum SHA3_RETURN {
    SHA3_RETURN_OK=0,
    SHA3_RETURN_BAD_PARAMS=1
};
typedef enum SHA3_RETURN sha3_return_t;
sha3_return_t sha3_Init(void *priv, unsigned bitSize);

void sha3_Init256(void *priv);
void sha3_Init384(void *priv);
void sha3_Init512(void *priv);

enum SHA3_FLAGS sha3_SetFlags(void *priv, enum SHA3_FLAGS);

void sha3_Update(void *priv, void const *bufIn, size_t len);

void const *sha3_Finalize(void *priv);


sha3_return_t sha3_HashBuffer( 
    unsigned bitSize,   
    enum SHA3_FLAGS flags, 
    const void *in, unsigned inBytes, 
    void *out, unsigned outBytes );
#endif

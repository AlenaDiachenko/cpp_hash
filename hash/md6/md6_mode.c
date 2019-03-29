#if 0

extern int md6_init( md6_state *st,             
		     int d                          
		     );

extern int md6_full_init( md6_state *st,       
			  int d,                    
			  unsigned char *key,       
			  int keylen,       
			  int L,     
			  int r                    
			  );

extern int md6_update( md6_state *st,            
		       unsigned char *data,            
		       uint64_t datalen          
		       );

extern int md6_final( md6_state *st,           
		      unsigned char *hashval,     
		      );

extern int md6_hash( int d,                        
		     unsigned char *data,     
		     uint64_t datalen         
		     unsigned char *hashval,  
		     );

extern int md6_full_hash( int d,                    
			  unsigned char *data,
			  uint64_t datalen,      
			  unsigned char *key,       
			  int keylen,       
			  int L,     
			  int r,                   
			  unsigned char *hashval,            
			  );
#endif

#include <assert.h>
#include <stdio.h> 
#include <string.h>

#include "md6.h"


#define w md6_w     
#define n md6_n     
#define c md6_c     


#define q md6_q     
#define k md6_k     
#define u md6_u     
#define v md6_v     
#define b md6_b     


#ifndef min
#define min(a,b) ((a)<(b)? (a) : (b))
#endif
#ifndef max
#define max(a,b) ((a)>(b)? (a) : (b))
#endif


int md6_default_r( int d ,
                   int keylen )
{ int r;
  r = 40 + (d/4);
  if (keylen>0)
    r = max(80,r);
  return r;
}



#if (w==64)                     
static const md6_word Q[15] =
  {
    0x7311c2812425cfa0ULL,
    0x6432286434aac8e7ULL, 
    0xb60450e9ef68b7c1ULL, 
    0xe8fb23908d9f06f1ULL, 
    0xdd2e76cba691e5bfULL, 
    0x0cd0d63b2c30bc41ULL, 
    0x1f8ccf6823058f8aULL, 
    0x54e5ed5b88e3775dULL, 
    0x4ad12aae0a6d6031ULL, 
    0x3e7f16bb88222e0dULL, 
    0x8af8671d3fb50c2cULL, 
    0x995ad1178bd25c31ULL, 
    0xc878c1dd04c4b633ULL, 
    0x3b72066c7a1552acULL, 
    0x0d6f3522631effcbULL, 
  };
#endif

#if (w==32)                      
static const md6_word Q[30] =
  {
    0x7311c281UL, 0x2425cfa0UL,
    0x64322864UL, 0x34aac8e7UL, 
    0xb60450e9UL, 0xef68b7c1UL, 
    0xe8fb2390UL, 0x8d9f06f1UL, 
    0xdd2e76cbUL, 0xa691e5bfUL, 
    0x0cd0d63bUL, 0x2c30bc41UL, 
    0x1f8ccf68UL, 0x23058f8aUL, 
    0x54e5ed5bUL, 0x88e3775dUL, 
    0x4ad12aaeUL, 0x0a6d6031UL, 
    0x3e7f16bbUL, 0x88222e0dUL, 
    0x8af8671dUL, 0x3fb50c2cUL, 
    0x995ad117UL, 0x8bd25c31UL, 
    0xc878c1ddUL, 0x04c4b633UL, 
    0x3b72066cUL, 0x7a1552acUL, 
    0x0d6f3522UL, 0x631effcbUL, 
  };
#endif



#if (w==16)                    

static const md6_word Q[60] =
  {
    0x7311, 0xc281, 0x2425, 0xcfa0,
    0x6432, 0x2864, 0x34aa, 0xc8e7, 
    0xb604, 0x50e9, 0xef68, 0xb7c1, 
    0xe8fb, 0x2390, 0x8d9f, 0x06f1, 
    0xdd2e, 0x76cb, 0xa691, 0xe5bf, 
    0x0cd0, 0xd63b, 0x2c30, 0xbc41, 
    0x1f8c, 0xcf68, 0x2305, 0x8f8a, 
    0x54e5, 0xed5b, 0x88e3, 0x775d, 
    0x4ad1, 0x2aae, 0x0a6d, 0x6031, 
    0x3e7f, 0x16bb, 0x8822, 0x2e0d, 
    0x8af8, 0x671d, 0x3fb5, 0x0c2c, 
    0x995a, 0xd117, 0x8bd2, 0x5c31, 
    0xc878, 0xc1dd, 0x04c4, 0xb633, 
    0x3b72, 0x066c, 0x7a15, 0x52ac, 
    0x0d6f, 0x3522, 0x631e, 0xffcb, 
  };
#endif

#if (w==8)                      

static const md6_word Q[120] =
  {
    0x73, 0x11, 0xc2, 0x81, 0x24, 0x25, 0xcf, 0xa0,
    0x64, 0x32, 0x28, 0x64, 0x34, 0xaa, 0xc8, 0xe7, 
    0xb6, 0x04, 0x50, 0xe9, 0xef, 0x68, 0xb7, 0xc1, 
    0xe8, 0xfb, 0x23, 0x90, 0x8d, 0x9f, 0x06, 0xf1, 
    0xdd, 0x2e, 0x76, 0xcb, 0xa6, 0x91, 0xe5, 0xbf, 
    0x0c, 0xd0, 0xd6, 0x3b, 0x2c, 0x30, 0xbc, 0x41, 
    0x1f, 0x8c, 0xcf, 0x68, 0x23, 0x05, 0x8f, 0x8a, 
    0x54, 0xe5, 0xed, 0x5b, 0x88, 0xe3, 0x77, 0x5d, 
    0x4a, 0xd1, 0x2a, 0xae, 0x0a, 0x6d, 0x60, 0x31, 
    0x3e, 0x7f, 0x16, 0xbb, 0x88, 0x22, 0x2e, 0x0d, 
    0x8a, 0xf8, 0x67, 0x1d, 0x3f, 0xb5, 0x0c, 0x2c, 
    0x99, 0x5a, 0xd1, 0x17, 0x8b, 0xd2, 0x5c, 0x31, 
    0xc8, 0x78, 0xc1, 0xdd, 0x04, 0xc4, 0xb6, 0x33, 
    0x3b, 0x72, 0x06, 0x6c, 0x7a, 0x15, 0x52, 0xac, 
    0x0d, 0x6f, 0x35, 0x22, 0x63, 0x1e, 0xff, 0xcb, 
  };
#endif





int md6_byte_order = 0;    



#define MD6_LITTLE_ENDIAN (md6_byte_order == 1)
#define MD6_BIG_ENDIAN    (md6_byte_order == 2)
 
void md6_detect_byte_order( void )

{ md6_word x = 1 | (((md6_word)2)<<(w-8));
  unsigned char *cp = (unsigned char *)&x;
  if ( *cp == 1 )        md6_byte_order = 1;      
  else if ( *cp == 2 )   md6_byte_order = 2;      
  else                   md6_byte_order = 0;      
}

md6_word md6_byte_reverse( md6_word x )

{ 
#define mask8  ((md6_word)0x00ff00ff00ff00ffULL)
#define mask16 ((md6_word)0x0000ffff0000ffffULL)
#if (w==64)
  x = (x << 32) | (x >> 32);
#endif
#if (w >= 32)
  x = ((x & mask16) << 16) | ((x & ~mask16) >> 16);
#endif
#if (w >= 16)
  x = ((x & mask8) << 8) | ((x & ~mask8) >> 8);
#endif
  return x;
}

void md6_reverse_little_endian( md6_word *x, int count )

{
  int i;
  if (MD6_LITTLE_ENDIAN)
    for (i=0;i<count;i++)
      x[i] = md6_byte_reverse(x[i]);
}



void append_bits( unsigned char *dest, unsigned int destlen,
		  unsigned char *src,  unsigned int srclen )

{ int i, di, accumlen;
  uint16_t accum;
  int srcbytes;

  if (srclen == 0) return;

  
  accum = 0;    
  accumlen = 0; 
  if (destlen%8 != 0)
    { accumlen = destlen%8;
      accum = dest[destlen/8];        
      accum = accum >> (8-accumlen);  
    }
  di = destlen/8;        
  
  
  srcbytes = (srclen+7)/8;   
  for (i=0;i<srcbytes;i++)
    { 
      if (i != srcbytes-1) 
	{ accum = (accum << 8) ^ src[i];  
	  accumlen += 8;
	}
      else 
	{ int newbits = ((srclen%8 == 0) ? 8 : (srclen%8));
	  accum = (accum << newbits) | (src[i] >> (8-newbits));
	  accumlen += newbits;
	}
      
      while ( ( (i != srcbytes-1) & (accumlen >= 8) ) ||
	      ( (i == srcbytes-1) & (accumlen > 0) ) )
	{ int numbits = min(8,accumlen);
	  unsigned char bits;
	  bits = accum >> (accumlen - numbits);    
	  bits = bits << (8-numbits);              
	  bits &= (0xff00 >> numbits);             
	  dest[di++] = bits;                       
	  accumlen -= numbits; 
	}
    }
}



int md6_full_init( md6_state *st,       
		   int d,                          
		   unsigned char *key,        
		   int keylen,     
		   int L,           
		   int r                          
		   )

{ 
  if (st == NULL) return MD6_NULLSTATE;
  if ( (key != NULL) && ((keylen < 0) || (keylen > k*(w/8))) )
    return MD6_BADKEYLEN;
  if ( d < 1 || d > 512 || d > w*c/2 ) return MD6_BADHASHLEN;

  md6_detect_byte_order();
  memset(st,0,sizeof(md6_state));  
  st->d = d;                       
  if (key != NULL && keylen > 0)   
    { memcpy(st->K,key,keylen);    
      st->keylen = keylen;
      
      md6_reverse_little_endian(st->K,k);
    }
  else
    st->keylen = 0;
  if ( (L<0) | (L>255) ) return MD6_BAD_L;
  st->L = L;
  if ( (r<0) | (r>255) ) return MD6_BAD_r;
  st->r = r;
  st->initialized = 1;  
  st->top = 1;
  
  if (L==0) st->bits[1] = c*w;     
  compression_hook = NULL;    
  return MD6_SUCCESS;
}


int md6_init( md6_state *st,
	      int d 
	      )

{ return md6_full_init(st,
		       d,
		       NULL,
		       0,
		       md6_default_L,
		       md6_default_r(d,0)
		       );
}



int md6_compress_block( md6_word *C,
			md6_state *st, 
			int ell, 
			int z
			)

{ int p, err;

  
  if ( st == NULL) return MD6_NULLSTATE;
  if ( st->initialized == 0 ) return MD6_STATENOTINIT;
  if ( ell < 0 ) return MD6_STACKUNDERFLOW;
  if ( ell >= md6_max_stack_height-1 ) return MD6_STACKOVERFLOW;

  st->compression_calls++;

  if (ell==1) 
    { if (ell<(st->L + 1)) 
	md6_reverse_little_endian(&(st->B[ell][0]),b);
      else 
	md6_reverse_little_endian(&(st->B[ell][c]),b-c);
    }

  p = b*w - st->bits[ell];         

  err = 
    md6_standard_compress( 
      C,                                      
      Q,                                      
      st->K,                                  
      ell, st->i_for_level[ell],              
      st->r, st->L, z, p, st->keylen, st->d, 
      st->B[ell]                              
			   );                         
  if (err) return err; 

  st->bits[ell] = 0; 
  st->i_for_level[ell]++;

  memset(&(st->B[ell][0]),0,b*sizeof(md6_word));     
  return MD6_SUCCESS;
}



int md6_process( md6_state *st,
		 int ell,
		 int final )

{ int err, z, next_level;
  md6_word C[c];

  if ( st == NULL) return MD6_NULLSTATE;
  if ( st->initialized == 0 ) return MD6_STATENOTINIT;

  if (!final) 
    { 
      if ( st->bits[ell] < b*w ) 
	return MD6_SUCCESS;
      
    }
  else 
    { if ( ell == st->top )
	{ if (ell == (st->L + 1))
	    { if ( st->bits[ell]==c*w && st->i_for_level[ell]>0 )
		return MD6_SUCCESS;
	      
	    }
           else 
	     { if ( ell>1 && st->bits[ell]==c*w)
		 return MD6_SUCCESS;
	       
	     }
	}
      
    }

  z = 0; if (final && (ell == st->top)) z = 1; 
  if ((err = md6_compress_block(C,st,ell,z))) 
      return err;
  if (z==1) /
    { memcpy( st->hashval, C, md6_c*(w/8) );
      return MD6_SUCCESS;
    }
  
  
  next_level = min(ell+1,st->L+1);
  if (next_level == st->L + 1 
      && st->i_for_level[next_level]==0
      && st->bits[next_level]==0 )
    st->bits[next_level] = c*w;   
  
  memcpy((char *)st->B[next_level] + st->bits[next_level]/8,
	 C,
	 c*(w/8));
  st->bits[next_level] += c*w;   
  if (next_level > st->top) st->top = next_level;

  return md6_process(st,next_level,final);
}


int md6_update( md6_state *st, 
		unsigned char *data, 
		uint64_t databitlen )

{ unsigned int j, portion_size;
  int err;

  
  if ( st == NULL ) return MD6_NULLSTATE;
  if ( st->initialized == 0 ) return MD6_STATENOTINIT;
  if ( data == NULL ) return MD6_NULLDATA;
  
  j = 0; 
  while (j<databitlen)
    { 
      portion_size = min(databitlen-j,
			 (unsigned int)(b*w-(st->bits[1]))); 

      if ((portion_size % 8 == 0) && 
	  (st->bits[1] % 8 == 0) &&
	  (j % 8 == 0))
	{
	  memcpy((char *)st->B[1] + st->bits[1]/8,
		 &(data[j/8]),                                 
		 portion_size/8);
	}
      else 
	{ append_bits((unsigned char *)st->B[1], 
		      st->bits[1],   
		      &(data[j/8]),  
		      portion_size); 
	}
      j += portion_size;
      st->bits[1] += portion_size;
      st->bits_processed += portion_size;

      
      if (st->bits[1] == b*w && j<databitlen)
	{ if ((err=md6_process(st,
			       1,   
			       0    
			       ))) 
	    return err; 
	}
    }
  return MD6_SUCCESS;
}


int md6_compute_hex_hashval( md6_state *st )

{ int i;
  static unsigned char hex_digits[] = "0123456789abcdef";

 
  if ( st == NULL ) return MD6_NULLSTATE;
  
  for (i=0;i<((st->d+7)/8);i++)
    { st->hexhashval[2*i]   
	= hex_digits[ ((st->hashval[i])>>4) & 0xf ];
      st->hexhashval[2*i+1] 
	= hex_digits[ (st->hashval[i]) & 0xf ];
    }
  
  
  st->hexhashval[(st->d+3)/4] = 0;
  return MD6_SUCCESS;
}


void trim_hashval(md6_state *st)
{ 
  int full_or_partial_bytes = (st->d+7)/8;
  int bits = st->d % 8;               
  int i;

  
  for ( i=0; i<full_or_partial_bytes; i++ )
    st->hashval[i] = st->hashval[c*(w/8)-full_or_partial_bytes+i];

  for ( i=full_or_partial_bytes; i<c*(w/8); i++ )
    st->hashval[i] = 0;

 
  if (bits>0)
    { for ( i=0; i<full_or_partial_bytes; i++ )
	{ st->hashval[i] = (st->hashval[i] << (8-bits));
	  if ( (i+1) < c*(w/8) )
	    st->hashval[i] |= (st->hashval[i+1] >> bits);
	}
    }
}


int md6_final( md6_state *st , unsigned char *hashval)

{ int ell, err;

  if ( st == NULL) return MD6_NULLSTATE;
  if ( st->initialized == 0 ) return MD6_STATENOTINIT;
  if ( st->finalized == 1 ) return MD6_SUCCESS;

  if (st->top == 1) ell = 1;
  else for (ell=1; ell<=st->top; ell++)
	 if (st->bits[ell]>0) break;
 
  err = md6_process(st,ell,1);
  if (err) return err;

  md6_reverse_little_endian( (md6_word*)st->hashval, c );

   trim_hashval( st );
  if (hashval != NULL) memcpy( hashval, st->hashval, (st->d+7)/8 );

  md6_compute_hex_hashval( st );

  st->finalized = 1;
  return MD6_SUCCESS;
}



int md6_full_hash( int d,                    
		   unsigned char *data,
		   uint64_t databitlen,   
		   unsigned char *key,      
		   int keylen,      
		   int L,    
		   int r,                  
		   unsigned char *hashval             
		   )
{ md6_state st;
  int err;

  err = md6_full_init(&st,d,key,keylen,L,r);
  if (err) return err;
  err = md6_update(&st,data,databitlen);
  if (err) return err;
  md6_final(&st,hashval);
  if (err) return err;
  return MD6_SUCCESS;
}

int md6_hash( int d,                       
              unsigned char *data,     
	      uint64_t databitlen,       
	      unsigned char *hashval                 
	     )
{ int err;

  err = md6_full_hash(d,data,databitlen,
		      NULL,0,md6_default_L,md6_default_r(d,0),hashval);
  if (err) return err;
  return MD6_SUCCESS;
}





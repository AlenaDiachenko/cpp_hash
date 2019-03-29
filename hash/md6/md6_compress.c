#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "md6.h"


#ifndef min
#define min(a,b) ((a)<(b)? (a) : (b))
#endif
#ifndef max
#define max(a,b) ((a)>(b)? (a) : (b))
#endif


#define   w   md6_w  
#define   n   md6_n  
#define   c   md6_c  
#define   b   md6_b  
#define   v   md6_v  
#define   u   md6_u  
#define   k   md6_k  
#define   q   md6_q  /


#if (n==89)
#define  t0   17     
#define  t1   18     
#define  t2   21   
#define  t3   31     
#define  t4   67     
#define  t5   89     
#endif

#if (w==64)                       
#define RL00 loop_body(10,11, 0)
#define RL01 loop_body( 5,24, 1)
#define RL02 loop_body(13, 9, 2)
#define RL03 loop_body(10,16, 3)
#define RL04 loop_body(11,15, 4)
#define RL05 loop_body(12, 9, 5)
#define RL06 loop_body( 2,27, 6)
#define RL07 loop_body( 7,15, 7)
#define RL08 loop_body(14, 6, 8)
#define RL09 loop_body(15, 2, 9)
#define RL10 loop_body( 7,29,10)
#define RL11 loop_body(13, 8,11)
#define RL12 loop_body(11,15,12)
#define RL13 loop_body( 7, 5,13)
#define RL14 loop_body( 6,31,14)
#define RL15 loop_body(12, 9,15)

const md6_word S0 = (md6_word)0x0123456789abcdefULL;
const md6_word Smask = (md6_word)0x7311c2812425cfa0ULL;

#elif (w==32)                      /* for variant word size */
#define RL00 loop_body( 5, 4, 0)
#define RL01 loop_body( 3, 7, 1)
#define RL02 loop_body( 6, 7, 2)
#define RL03 loop_body( 5, 9, 3)
#define RL04 loop_body( 4,13, 4)
#define RL05 loop_body( 6, 8, 5)
#define RL06 loop_body( 7, 4, 6)
#define RL07 loop_body( 3,14, 7)
#define RL08 loop_body( 5, 7, 8)
#define RL09 loop_body( 6, 4, 9)
#define RL10 loop_body( 5, 8,10)
#define RL11 loop_body( 5,11,11)
#define RL12 loop_body( 4, 5,12)
#define RL13 loop_body( 6, 8,13)
#define RL14 loop_body( 7, 2,14)
#define RL15 loop_body( 5,11,15)

const md6_word S0 = (md6_word)0x01234567UL;
const md6_word Smask = (md6_word)0x7311c281UL;


#elif (w==16)                     
#define RL00 loop_body( 5, 6, 0)
#define RL01 loop_body( 4, 7, 1)
#define RL02 loop_body( 3, 2, 2)
#define RL03 loop_body( 5, 4, 3)
#define RL04 loop_body( 7, 2, 4)
#define RL05 loop_body( 5, 6, 5)
#define RL06 loop_body( 5, 3, 6)
#define RL07 loop_body( 2, 7, 7)
#define RL08 loop_body( 4, 5, 8)
#define RL09 loop_body( 3, 7, 9)
#define RL10 loop_body( 4, 6,10)
#define RL11 loop_body( 3, 5,11)
#define RL12 loop_body( 4, 5,12)
#define RL13 loop_body( 7, 6,13)
#define RL14 loop_body( 7, 4,14)
#define RL15 loop_body( 2, 3,15)

const md6_word S0 = (md6_word)0x01234;
const md6_word Smask = (md6_word)0x7311;

#elif (w==8)                    

#define RL00 loop_body( 3, 2, 0)
#define RL01 loop_body( 3, 4, 1)
#define RL02 loop_body( 3, 2, 2)
#define RL03 loop_body( 4, 3, 3)
#define RL04 loop_body( 3, 2, 4)
#define RL05 loop_body( 3, 2, 5)
#define RL06 loop_body( 3, 2, 6)
#define RL07 loop_body( 3, 4, 7)
#define RL08 loop_body( 2, 3, 8)
#define RL09 loop_body( 2, 3, 9)
#define RL10 loop_body( 3, 2,10)
#define RL11 loop_body( 2, 3,11)
#define RL12 loop_body( 2, 3,12)
#define RL13 loop_body( 3, 4,13)
#define RL14 loop_body( 2, 3,14)
#define RL15 loop_body( 3, 4,15)

const md6_word S0 = (md6_word)0x01;
const md6_word Smask = (md6_word)0x73;

#endif


void md6_main_compression_loop( md6_word* A , int r )

{ md6_word x, S;
  int i,j;
  S = S0;
  for (j = 0, i = n; j<r*c; j+=c)
    {

#define loop_body(rs,ls,step)                                       \
      x = S;                                 \
      x ^= A[i+step-t5];                     \
      x ^= A[i+step-t0];                     \
      x ^= ( A[i+step-t1] & A[i+step-t2] );  \
      x ^= ( A[i+step-t3] & A[i+step-t4] );  \
      x ^= (x >> rs);                        \
      A[i+step] = x ^ (x << ls);            

    
      RL00 RL01 RL02 RL03 RL04 RL05 RL06 RL07
      RL08 RL09 RL10 RL11 RL12 RL13 RL14 RL15

     
      S = (S << 1) ^ (S >> (w-1)) ^ (S & Smask);
      i += 16;
    }
}


int md6_compress( md6_word *C,
		  md6_word *N,
		  int r,
		  md6_word *A
		 )

{ md6_word* A_as_given = A;

  if ( N == NULL) return MD6_NULL_N;
  if ( C == NULL) return MD6_NULL_C;
  if ( r<0 || r > md6_max_r) return MD6_BAD_r;

  if ( A == NULL) A = calloc(r*c+n,sizeof(md6_word));
  if ( A == NULL) return MD6_OUT_OF_MEMORY;

  memcpy( A, N, n*sizeof(md6_word) );    

  md6_main_compression_loop( A, r );          

  memcpy( C, A+(r-1)*c+n, c*sizeof(md6_word) ); 

  if ( A_as_given == NULL )           
    { memset(A,0,(r*c+n)*sizeof(md6_word)); 
      free(A);           
    }

  return MD6_SUCCESS;
}

md6_control_word md6_make_control_word(	int r, 
					int L, 
					int z, 
					int p, 
					int keylen, 
					int d 
					)

{ md6_control_word V;
  V = ( (((md6_control_word) 0) << 60) | 
	(((md6_control_word) r) << 48) |          
	(((md6_control_word) L) << 40) |          
	(((md6_control_word) z) << 36) |           
	(((md6_control_word) p) << 20) |           
	(((md6_control_word) keylen) << 12 ) |     
        (((md6_control_word) d)) );                
  return V;
}

md6_nodeID md6_make_nodeID( int ell,                    
			      int i    
			    )

{ md6_nodeID U;
  U = ( (((md6_nodeID) ell) << 56) | 
	((md6_nodeID) i) );
  return U;
}


void md6_pack( md6_word*N,
	       const md6_word* Q,
	       md6_word* K,
	       int ell, int i,
	       int r, int L, int z, int p, int keylen, int d,
	       md6_word* B )

{ int j;
  int ni;
  md6_nodeID U;
  md6_control_word V;    

  ni = 0;

  for (j=0;j<q;j++) N[ni++] = Q[j];       

  for (j=0;j<k;j++) N[ni++] = K[j];      

  U = md6_make_nodeID(ell,i);            
  
  memcpy((unsigned char *)&N[ni],
	 &U,
	 min(u*(w/8),sizeof(md6_nodeID)));
  ni += u;

  V = md6_make_control_word(
			r,L,z,p,keylen,d);
 
  memcpy((unsigned char *)&N[ni],
	 &V,
	 min(v*(w/8),sizeof(md6_control_word)));
  ni += v;

  memcpy(N+ni,B,b*sizeof(md6_word));      
}

int md6_standard_compress( md6_word* C,
			   const md6_word* Q,
			   md6_word* K,
			   int ell, int i,
			   int r, int L, int z, int p, int keylen, int d,
			   md6_word* B 
			   )

{ md6_word N[md6_n];
  md6_word A[5000];       

  
  if ( (C == NULL) ) return MD6_NULL_C;
  if ( (B == NULL) ) return MD6_NULL_B;
  if ( (r<0) | (r>md6_max_r) ) return MD6_BAD_r;
  if ( (L<0) | (L>255) ) return MD6_BAD_L;
  if ( (ell < 0) || (ell > 255) ) return MD6_BAD_ELL;
  if ( (p < 0) || (p > b*w ) ) return MD6_BAD_p;
  if ( (d <= 0) || (d > c*w/2) ) return MD6_BADHASHLEN;
  if ( (K == NULL) ) return MD6_NULL_K;
  if ( (Q == NULL) ) return MD6_NULL_Q;

  
  md6_pack(N,Q,K,ell,i,r,L,z,p,keylen,d,B);

 
  if (compression_hook != NULL)
    compression_hook(C,Q,K,ell,i,r,L,z,p,keylen,d,B);

  return md6_compress(C,N,r,A);
}


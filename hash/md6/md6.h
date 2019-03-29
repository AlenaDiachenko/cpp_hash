
#ifndef MD6_H_INCLUDED
#define MD6_H_INCLUDED



#if defined  _MSC_VER
#include "inttypes.h"
#else
#include <inttypes.h>
#endif


#define   md6_w    64



#if (md6_w==64)                  
typedef uint64_t md6_word;
#define PR_MD6_WORD "%.16" PRIx64

#elif (md6_w==32)                
typedef uint32_t md6_word;
#define PR_MD6_WORD "%.8" PRIx32

#elif (md6_w==16)                  
typedef uint16_t md6_word;
#define PR_MD6_WORD "%.4" PRIx16

#elif (md6_w==8)                  
typedef uint8_t md6_word;
#define PR_MD6_WORD "%.2" PRIx8

#endif

                           

#define md6_n      89    
#define md6_c      16    
                         
#define md6_max_r 255    



extern int md6_default_r( int d,      
			  int keylen  
			  );    

void md6_main_compression_loop( md6_word *A,         
				int r              
				);

int md6_compress( md6_word *C,                            
		  md6_word *N,                                
		  int r,                            
		  md6_word *A
                );


typedef uint64_t md6_control_word;                     
md6_control_word md6_make_control_word( int r,        
					int L,      
					int z,      
					int p,         
					int keylen,    
					int d          
					);

typedef uint64_t md6_nodeID;                               
md6_nodeID md6_make_nodeID( int ell,                  
			    int i    
			    );

void md6_pack( md6_word* N,                                  
	       const md6_word* Q,         
	       md6_word* K,                                    
	       int ell, int i,                               
	       int r, int L, int z, int p, int keylen, int d,
	       md6_word* B                             
	       );

int md6_standard_compress( 
        md6_word *C,                                    
	const md6_word *Q,              
	md6_word *K,                                       
	int ell, int i,                                  
	int r, int L, int z, int p, int keylen, int d,    
	md6_word* B                                  
			   );

#define md6_q 15        
#define md6_k  8         
#define md6_u (64/md6_w) 
#define md6_v (64/md6_w) 
#define md6_b 64        

#define md6_default_L 64   

#define md6_max_stack_height 29
    
typedef struct {

  int d;           
  int hashbitlen;  

  unsigned char hashval[ md6_c*(md6_w/8) ];
     

  unsigned char hexhashval[(md6_c*(md6_w/8))+1];
     

  int initialized;         
  uint64_t bits_processed;               
  uint64_t compression_calls;    
  int finalized;        

  md6_word K[ md6_k ];  
     
  int keylen;
     

  int L;
  int r;
  int top;


  md6_word B[ md6_max_stack_height ][ md6_b ];
     

  unsigned int bits[ md6_max_stack_height ];    
   

  uint64_t i_for_level[ md6_max_stack_height ];
    
} md6_state;

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
			   uint64_t databitlen      
		       );

extern int md6_final( md6_state *st,            
		      unsigned char *hashval       
			  );


extern int md6_hash( int d,                         
		     unsigned char *data,     
		     uint64_t databitlen,        
		     unsigned char *hashval                 
		     );

extern int md6_full_hash( int d,                    
			  unsigned char *data,
			  uint64_t databitlen,   
			  unsigned char *key,      
			  int keylen,       
			  int L,     
			  int r,                   
			  unsigned char *hashval             
			  );



#define MD6_SUCCESS 0

#define MD6_FAIL 1           
#define MD6_BADHASHLEN 2     
#define MD6_NULLSTATE 3      
#define MD6_BADKEYLEN 4    
#define MD6_STATENOTINIT 5   
#define MD6_STACKUNDERFLOW 6 
#define MD6_STACKOVERFLOW 7  
#define MD6_NULLDATA 8      
#define MD6_NULL_N 9        
#define MD6_NULL_B 10       
#define MD6_BAD_ELL 11      
#define MD6_BAD_p 12         
#define MD6_NULL_K 13        
#define MD6_NULL_Q 14        
#define MD6_NULL_C 15        
#define MD6_BAD_L 16        
                            
#define MD6_BAD_r 17        
                            
#define MD6_OUT_OF_MEMORY 18 



#if ( (md6_w!=8) && (md6_w!=16) && (md6_w!=32) && (md6_w!=64) )
  #error "md6.h Fatal error: md6_w must be one of 8,16,32, or 64."
#elif ( md6_n<=0 )
  #error "md6.h Fatal error: md6_n must be positive."
#elif ( md6_b<=0 )
  #error "md6.h Fatal error: md6_b must be positive."
#elif ( md6_c<=0 )
  #error "md6.h Fatal error: md6_c must be positive."
#elif ( md6_v<0 )
  #error "md6.h Fatal error: md6_v must be nonnegative."
#elif ( md6_u<0 )
  #error "md6.h Fatal error: md6_u must be nonnegative."
#elif ( md6_k<0 )
  #error "md6.h Fatal error: md6_k must be nonnegative."
#elif ( md6_q<0 )
  #error "md6.h Fatal error: md6_q must be nonnegative."
#elif ( md6_b>=md6_n )
  #error "md6.h Fatal error: md6_b must be smaller than md6_n."
#elif ( md6_c>=md6_b )
  #error "md6.h Fatal error: md6_c must be smaller than md6_b."
#elif ( (md6_b%md6_c)!=0 )
  #error "md6.h Fatal error: md6_b must be a multiple of md6_c."
#elif ( md6_n != md6_b + md6_v + md6_u + md6_k + md6_q )
  #error "md6.h Fatal error: md6_n must = md6_b + md6_v + md6_u + md6_k + md6_q."
#elif ( md6_max_stack_height < 3 )
  #error "md6.h Fatal error: md6_max_stack_height must be at least 3."
#elif ( md6_r * md6_c + md6_n >= 5000 )

  #error "md6.h Fatal error: r*c+n must be < 5000."
#if 0
 
  #elif ( (md6_v != 0) && (md6_v != (sizeof(md6_control_word)/(md6_w/8))) )
    #error "md6.h Fatal error: md6_v must be 0 or match md6_control_word size."
  #elif ( (md6_u != 0) && (md6_u != (sizeof(md6_nodeID)/(md6_w/8))) )
    #error "md6.h Fatal error: md6_u must be 0 or match md6_nodeID size."
#endif
#endif


void (* compression_hook)(md6_word *C,
			  const md6_word *Q,
			  md6_word *K,
			  int ell,
			  int i,
			  int r,
			  int L,
			  int z,
			  int p,
			  int keylen,
			  int d,
			  md6_word *N
			  );


#endif


#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <math.h>

void end512(unsigned char * ret, unsigned char * bin){
	memset(ret,0,16);
	int taille =(int) strlen(bin)*8;
	sprintf(ret,"%x",taille);
	int tailleHexa=(int) strlen(ret)%2;
	if (tailleHexa)
		sprintf(ret,"0%x",taille);
}

void diviserBloc512(uint32_t * ws, unsigned char * msg, unsigned char * end){
	unsigned char * sc=(unsigned char *) calloc(8,sizeof(unsigned char));
	for(int i=0,j=0; i<56; i+=4,j++){
		for (int k=0;k<4;k++){
			sprintf(sc+k*2,"%02x",msg[i+k]&0xff);
		}
			sscanf(sc,"%x",ws+j);
			ws[j] = __builtin_bswap32(*(ws+j));
	}
	sscanf(end,"%8x",ws+14);
	sscanf(end+8,"%8x",ws+15);
	free(sc);
}

void remplirHash(unsigned char * hashHexa, uint32_t a, uint32_t b, uint32_t c, uint32_t d){

	//On copie les 4 blocs de 4 octets chacun à la suite pour former le hash complet
	memcpy(hashHexa,(unsigned char*) &a, 4);
	memcpy(hashHexa+ 4,(unsigned char*) &b,4);
	memcpy(hashHexa+ 8,(unsigned char*) &c,4);
	memcpy(hashHexa+ 12,(unsigned char*) &d,4);
	hashHexa[16] = 0 ;
}

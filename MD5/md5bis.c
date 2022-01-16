#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <stdint.h>
#include <string.h>
#include "fonctionsGen.h"
#include "md5bis.h"

uint32_t r[] = {7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
                    5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20,
                    4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
                    6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21
									};

uint32_t k[] = {
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
    0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
    0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
    0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
    0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
    0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
    0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
    0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
    0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
	};

uint32_t aa=REGA;
uint32_t bb=REGB;
uint32_t cc=REGC;
uint32_t dd=REGD;

void psswdTo512(uint32_t * ws, unsigned char * passwd){
	int taille = (int) strlen(passwd);

	unsigned char * tab2 = (unsigned char *) calloc(16,sizeof(unsigned char));

	end512(tab2, passwd);
	passwd[taille]=0x80;
	diviserBloc512(ws,passwd,tab2);

	free(tab2);
}

void premierTour(uint32_t * ws){
	uint32_t tmp, resF;
	for (int i=0;i<16;i++){
		resF=FONCTION_F(bb,cc,dd);
		tmp=dd;
		dd=cc;
		cc=bb;
		bb=bb + LEFTROTATE((aa + resF + k[i] + ws[i]), r[i]);
		aa=tmp;
	}
}

void deuxiemeTour(uint32_t * ws){
		uint32_t g=0;
		uint32_t tmp, resG;
		for (int i=0,j=16;i<16;i++,j++){
			resG=FONCTION_G(bb,cc,dd);
      g = (5*j + 1) % 16;
			tmp=dd;
			dd=cc;
			cc=bb;
			bb=bb + LEFTROTATE((aa + resG + k[j] + ws[g]), r[j]);
			aa=tmp;
		}
}

void troisiemeTour(uint32_t * ws){
			uint32_t g=0;
			uint32_t tmp, resH;
			for (int i=0,j=32;i<16;i++,j++){
				resH=FONCTION_H(bb,cc,dd);
	      g = (3*j + 5) % 16;
				tmp=dd;
				dd=cc;
				cc=bb;
				bb=bb + LEFTROTATE((aa + resH + k[j] + ws[g]), r[j]);
				aa=tmp;
			}
}

void quatriemeTour(uint32_t * ws){
			uint32_t g=0;
			uint32_t tmp, resI;
			for (int i=0,j=48;i<16;i++,j++){
				resI=FONCTION_I(bb,cc,dd);
	      g = (7*j) % 16;
				tmp=dd;
				dd=cc;
				cc=bb;
				bb=bb + LEFTROTATE((aa + resI + k[j] + ws[g]), r[j]);
				aa=tmp;
			}
}

void md5(unsigned char * hash, unsigned char * passwd){
	uint32_t * ws = (uint32_t *) calloc(16, sizeof(uint32_t));

	aa=REGA;
	bb=REGB;
	cc=REGC;
	dd=REGD;

	//Initialisation
	psswdTo512(ws,passwd);


	//Tours
	premierTour(ws);
	deuxiemeTour(ws);
	troisiemeTour(ws);
	quatriemeTour(ws);

	//Resultats
	aa+=REGA;
	bb+=REGB;
	cc+=REGC;
	dd+=REGD;

	//Retour
	remplirHash(hash,aa,bb,cc,dd);
	free(ws);
}

#ifndef MD5BIS_H
#define MD5BIS_H

#include <stdint.h>

#define REGA 0x67452301
#define REGB 0xefcdab89
#define REGC 0x98badcfe
#define REGD 0x10325476
#define LEFTROTATE(x, c) (((x) << (c)) | ((x) >> (32 - (c))))
#define FONCTION_F(x,y,z) ((x & y) | ((~x) & z))
#define FONCTION_G(x,y,z) ((x & z) | ((~z) & y))
#define FONCTION_H(x,y,z) (x ^ y ^ z)
#define FONCTION_I(x,y,z) (y ^ (x | (~z)))

//Completion
void psswdTo512(uint32_t * ws, unsigned char * passwd);

//Calclus
void premierTour(uint32_t * ws);
void deuxiemeTour(uint32_t * ws);
void troisiemeTour(uint32_t * ws);
void quatriemeTour(uint32_t * ws);

//Fonction principale
void md5(unsigned char * hash, unsigned char * passwd);
#endif

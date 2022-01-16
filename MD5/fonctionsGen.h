#ifndef FONCTIONSGEN_H
#define FONCTIONSGEN_H

#define AFFICHAGE 0

//Fonctions annexes
void end512(unsigned char * ret, unsigned char * bin);
void diviserBloc512(uint32_t * ws, unsigned char * msg, unsigned char * end);
void remplirHash(unsigned char * hashHexa, uint32_t a, uint32_t b, uint32_t c, uint32_t d);

#endif

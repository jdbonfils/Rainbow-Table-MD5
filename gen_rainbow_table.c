#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

#include "MD5/fonctionsGen.h"
#include "MD5/md5bis.h"

#define LOWER_CASE_OFFSET 97 	//Debut des lettre majuscules dans la table ASCII
#define UPPER_CASE_OFFSET 65 	//Debut des lettre minuscules dans la table ASCII
#define NUMBER_OFFSET 48 		//Debut des nombres dans la table ASCII
#define ALL_CHAR_OFFSET 33 		//Debut des chars (lisibles) dans la table ASCII
#define ALL_CHAR_COUNT 93 		//Nombre totale de charactere dans la table ASCII

#define MD5_DIGEST_LENGTH 16
#define PSSWD_AREA 56

//Génere une mot de passe aléatoire dans l'espace de recherche//Reduit un hash en un mot de passe seulement les paramètres de l'espace de recherche
/*
	password_min_length		Taille min du mot de passe
	password_max_length		Taille max du mot de passe
	ascii_offset			Premier charactere dans la table ASCII de l'espace de recherche (ex: a-z -> ascii_offset=97 )
	chars_range				Taille de l'espace de recherche (ex: a-z -> chars_range=26 )
	new_passwd				Mot de passe généré àléatoirement dans l'espace de recherche
*/
void get_rnd_str(unsigned int password_min_length, unsigned long int psswd_max_length,  unsigned int ascii_offset, unsigned int char_range,char* new_passwd)
{
	unsigned int psswd_length = (rand()% (psswd_max_length - password_min_length + 1)) + password_min_length;

	for(unsigned int charIdx=0; charIdx != psswd_length;charIdx++)
	{
		new_passwd[charIdx] = (rand() % char_range)+ascii_offset;
	}
}

//Reduit un hash en un mot de passe seulement les paramètres de l'espace de recherche
/*
	chain_index				Evite qu'un meme hash donne la meme réduction (évite les ramifications)
	password_min_length		Taille min du mot de passe
	password_max_length		Taille max du mot de passe
	ascii_offset			Premier charactere dans la table ASCII de l'espace de recherche (ex: a-z -> ascii_offset=97 )
	chars_range				Taille de l'espace de recherche (ex: a-z -> chars_range=26 )
	hash 					Le hash à reduire en mot de passe
	new_passwd				Mot de passe généré à partir de la reduciton du hash
*/
void str_reduction(unsigned int chain_index,unsigned int password_min_length, unsigned long int psswd_max_length,  unsigned int ascii_offset, unsigned int char_range, unsigned char* hash,char* new_passwd)
{
	//Alea ne peut pas etre utilisé donc pseudo random pour que l'espace de recherche soit réparti équitablement
	unsigned int psswd_length = 0; //(rand() % (psswd_max_length - password_min_length + 1)) + password_min_length;

	//Pour chaque Bytes du hash
	for(unsigned int charIdx=0; charIdx != MD5_DIGEST_LENGTH;charIdx++)
	{
		new_passwd[charIdx] = ((hash[charIdx]+chain_index) % char_range)+ascii_offset; //Permet d'avoir un charactere dans l'espace de recherche
		psswd_length += hash[charIdx]; 
	}
	//Permet de definir une taille de MDP en sortie en fonction des données
	psswd_length = (psswd_length % (psswd_max_length - password_min_length + 1)) + password_min_length ;
	
	//On coupe la chaine pour obtenir la taille voulue
	//memset(new_passwd+psswd_length, 0, PSSWD_AREA - psswd_length );
	memset(new_passwd+psswd_length, 0, MD5_DIGEST_LENGTH - psswd_length ); 
}

//Affiche les données (unsigned char*) en hexadecimal ("00011010" -> 0x1A)
void print_data_as_hex(unsigned char* data,size_t data_size)
{
	for (unsigned int i=0; i < data_size; i++) {
        printf("%02x", data[i]);
    }
}

/* Fonction générant la rainbow table

	fp 						Fichier dans lequel générer la rainbow table
	M 						Nomre de chaine	
	T 						Taille d'une chaine
	password 				Mot de passe de départ pour le maillon M=1 et T=1
	password_min_length		Taille min du mot de passe
	password_max_length		Taille max du mot de passe
	ascii_offset			Premier charactere dans la table ASCII de l'espace de recherche (ex: a-z -> ascii_offset=97 )
	chars_range				Taille de l'espace de recherche (ex: a-z -> chars_range=26 )
*/
void gen_rainbow_table(FILE* fp, unsigned int M, unsigned int T ,unsigned int password_min_length, unsigned int password_max_length, unsigned int ascii_offset,unsigned int chars_range)
{
	//Ecriture des paramètre sur la premiere ligne
	fprintf(fp,"%d;%d;%d;%d;%d;%d\n",T,M,password_min_length,password_max_length,ascii_offset,chars_range);
	
	//Variable dans laquelle est stockée le hashé temporairement
	unsigned char * md5_hash = (unsigned char *) calloc(MD5_DIGEST_LENGTH+1, sizeof(unsigned char));

	//Mot de passe à partir duquel est dérivé tous les hashés et reductions
	unsigned char * password	= (unsigned char *) calloc(PSSWD_AREA, sizeof(unsigned char));

	//Permet d'obtenir un mdp random dans l'espace recherché
	get_rnd_str(password_min_length, password_max_length,ascii_offset,chars_range,password);
	
	//Pour chaque ligne
	for(unsigned int I=0;I<M;I++)
	{
		fprintf(fp,"%s ",password); //Ecriture dans le fichier de la tête de la chaine

		//Pour chaque F k = R k ◦ F (Reduction + Hashage)
		for(unsigned int K=0;K<T;K++)
		{
			md5(md5_hash,password);
			//memset(password, 0, PSSWD_AREA );
			memset(password, 0, strlen(password) );
			str_reduction(K+1,password_min_length, password_max_length,ascii_offset,chars_range,md5_hash,password);
		}
		fprintf(fp,"%s\n",password); //Ecriture dans le fichier de la queue de la chaine

		//Nouveau mot de passe en début de chaine (dans l'espace de recherche)
		//memset(password, 0, PSSWD_AREA );
		memset(password, 0, strlen(password) );
		get_rnd_str(password_min_length, password_max_length,ascii_offset,chars_range,password);
	}
	free(md5_hash);
	free(password);
}

int main(int argc, char *argv[])
{
	if(argc < 5) //5 options sont indispensables
	{
	    printf("Veuillez indiquer en parametre : \n - La taille d'une chaine \n - Le nombre de chaines à générer \n - Taille minimum du mot de passe \n - Taille maximum du mot de passe \n");
	    return 0;
	}

	srand(time(0));
	unsigned int T = atoi(argv[1]); //Taille d'une chaine (Nombre de hashages/réductions)
	unsigned int M = atoi(argv[2]); //Nombre de chaines à générer dans la table
	unsigned int psswd_min_length = atoi(argv[3]);  //Taille min du mot de passe (Ne peut pas etre superieur à 16)
	unsigned int psswd_max_length = atoi(argv[4]); //Taille max du mot de passe (Ne peut pas etre superieur à 16)

	FILE* fp; //Fichier dans lequel stocker les chaines arc-en-ciel

	//Choix de l'utilisateur sur l'espace de recherche du MDP
	char ch1;
	unsigned int ascii_offset; 
	unsigned int chars_range=26;

	//Nom du fichier dans lequel stocker les chaines arc-en-ciel
	char fic_name[40] = "table_";
	strcat(fic_name, argv[1]);
	strcat(fic_name, "X");
	strcat(fic_name, argv[2]);
	strcat(fic_name, "_");
	strcat(fic_name, argv[3]);
	strcat(fic_name, "_");

	//Format de mot de passe (permet de réduire l'espace de recherche)
	printf("Password range: Lower case only (0) - Upper case only (1) - numbers only (2) - all chars (3) \n");
	scanf("%c", &ch1);
	switch(ch1)
	{
		case '0':
	    	ascii_offset = LOWER_CASE_OFFSET;
	    	strcat(fic_name, "LOWER_CASE");
	    	break;
	    case '1':
	    	ascii_offset = UPPER_CASE_OFFSET;
	    	strcat(fic_name, "UPPER_CASE");
	    	break;
	    case '2':
	    	ascii_offset = NUMBER_OFFSET;
	    	chars_range=10;
	    	strcat(fic_name, "NUMBERS");
			break;
		case '3':
			ascii_offset = ALL_CHAR_OFFSET;
			chars_range = ALL_CHAR_COUNT;
			strcat(fic_name, "ALL_CHARS");
			break;
	}
	//Affichage des paramètres parsés
	printf("---Paramètres--- \n T: %d\n M: %d\n Password minimum length: %d\n Password maximum length: %d\n ASCII OFFSET: %d\n NBR CHARS: %d\n----------------- \n",T,M,psswd_min_length,psswd_max_length,ascii_offset,chars_range);

	fp = fopen(fic_name,"wb"); //Fichier stockant les chaines arc-en-ciel
	if( fp == NULL ) {
        printf( "Cannot open file %s \n", fic_name );
        exit( 0 );
    }

	//Phase de calculs (Hashage + Reduciton), Génère la table de hashage
	gen_rainbow_table(fp,M,T,psswd_min_length,psswd_max_length,ascii_offset,chars_range);

	printf("Fichier %s généré \n", fic_name);
	fclose(fp);
    return 0;
}




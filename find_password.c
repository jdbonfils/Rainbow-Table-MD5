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
#define MD5_DIGEST_LENGTH 16	//Taille en octets d'un hash
#define PSSWD_AREA 56			//Taille max d'un mot de passe

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

//Retrouve le mot de passe donnant le hash recherché grâce à la tête de la chaine passé en paramètre
/*
	idx_maillon 			L'indice du maillon ayant donné une queue de chaine se trouvant dans la table
	head_chain 				Le mot de passe en tete de chaine permettant de dériver jusqu'au hash recherché
	origin_hash	 			Le hash recherché
	password_min_length		Taille min du mot de passe
	password_max_length		Taille max du mot de passe
	ascii_offset			Premier charactere dans la table ASCII de l'espace de recherche (ex: a-z -> ascii_offset=97 )
	nbr_chars				Taille de l'espace de recherche (ex: a-z -> chars_range=26 )
*/
int find_psswd_from_head(unsigned int idx_maillon, unsigned char * head_chain, unsigned char * origin_hash,unsigned int psswd_min_length,unsigned int psswd_max_length,unsigned int ascii_offset,unsigned int nbr_chars)
{
	unsigned char * hashTMP = (unsigned char *) calloc(MD5_DIGEST_LENGTH+1, sizeof(unsigned char));
	unsigned int K = 0 ;

	md5(hashTMP,head_chain);
	//On hash et on réduit successivement à partir de la tête de la chaine jusqu'à arrivé au maillon ayant donné une queu de chaine dans la table
	for(unsigned int K=0; K < idx_maillon ; K++ )
	{ 
		memset(head_chain, 0, strlen(head_chain));
		str_reduction(K+1,psswd_min_length,psswd_max_length,ascii_offset,nbr_chars,hashTMP,head_chain);
		md5(hashTMP,head_chain);
	}
	//Une fois arrive sur le maillon ayant donné une queue de chaine dans la table
	//On regarde si ce maillon donne le hashé recherché
	if(memcmp(hashTMP,origin_hash,MD5_DIGEST_LENGTH+1)==0) 
		{
			head_chain[strlen(head_chain)-1] = 0;
			printf("Mot de passe original : %s \n",head_chain);
			free(hashTMP);
			return 1;
		}
	//printf("Faux positif ! \n"); 
	//Des faux positifs peuvent arriver puisque la fonction de reduction est une surjeciton
	free(hashTMP);	
	return 0;
}

//Converti une chaine de charactere correspondant à un Hash MD5 en données au format unsigned char *
void md5_str_hash_to_data(const char* hexstr,unsigned char * output)
{
    for (size_t i=0, j=0; j<MD5_DIGEST_LENGTH; i+=2, j++)
        output[j] = (hexstr[i] % 32 + 9) % 25 * 16 + (hexstr[i+1] % 32 + 9) % 25;
    output[MD5_DIGEST_LENGTH] = '\0';
}

int main(int argc, char *argv[])
{
	//Lecture des arguments
	if(argc < 3)
	{
	    printf("Veuillez indiquer en parametre : \n - Le fichier contenant la rainbow table \n - Le hash MD5 (ex: c73eb66afae266dc93c1027bb228e6c9 ) \n");
	    return 0;
	}
	
    //Hashé recherché
    unsigned char * hash_searched	= (unsigned char *) calloc(PSSWD_AREA, sizeof(unsigned char));
    md5_str_hash_to_data(argv[2],hash_searched);

    //Hash temporairement calcule
	unsigned char * hash_tmp = (unsigned char *) calloc(MD5_DIGEST_LENGTH+1, sizeof(unsigned char));

	//Jamais sup à la taille du hashé MD5 puisque réduction
	unsigned char * str_password	= (unsigned char *) calloc(PSSWD_AREA, sizeof(unsigned char));
    
    FILE* fp ;
    char * line = NULL;
    size_t len = 0;
    ssize_t read;
	unsigned char* original =  (unsigned char *) calloc(PSSWD_AREA, sizeof(unsigned char));
    fp = fopen(argv[1], "r");
    if (fp == NULL)
        exit(EXIT_FAILURE);

    //La première ligne du fichier contient les parametre de la table et de l'espace de recherche
    getline(&line, &len, fp);
    unsigned int T = atoi(strtok ( line, ";" ));
    unsigned int M = atoi(strtok ( NULL, ";" ));
    unsigned int psswd_min_length = atoi(strtok ( NULL, ";" ));
 	unsigned int psswd_max_length = atoi(strtok ( NULL, ";" ));
 	unsigned int ascii_offset = atoi(strtok ( NULL, ";" ));
	unsigned int nbr_chars = atoi(strtok ( NULL, ";" ));
    printf("---Paramètres--- \n T: %d\n M: %d\n Password minimum length: %d\n Password maximum length: %d\n ASCII OFFSET: %d\n NBR CHARS: %d\n----------------- \n",T,M,psswd_min_length,psswd_max_length,ascii_offset,nbr_chars);

    //Pour chaque maillon des chaines
    for(unsigned int i=T;i != 0;i--)
    {
    	strcpy(hash_tmp,hash_searched);

    	str_reduction(i,psswd_min_length,psswd_max_length,ascii_offset,nbr_chars,hash_tmp,str_password);
    	
    	for(unsigned int y=i;y != T;y++) //Hash + Réduction pour arriver au maillon courant
    	{
    		md5(hash_tmp,str_password);
    		//memset(str_password, 0, PSSWD_AREA);
			memset(str_password, 0, strlen(str_password));
			str_reduction(y+1,psswd_min_length,psswd_max_length,ascii_offset,nbr_chars,hash_tmp,str_password);
    	}

    	fseek(fp, 0, SEEK_SET);
    	getline(&line, &len, fp);
    	while ((read = getline(&line, &len, fp)) != -1) { //Pour chaque ligne de la table
    		strtok(line, " ");
	    	if(strcmp(strtok(NULL, ";\n"),str_password)==0) //Si le mot de passe dérivé correspond à la queue d'une chaine
	    	{
	    		strcpy(original,strtok(line, " ")); //On récupere la tête de chaine courante, on repart de la tête de la chaine pour retrouver le MDP
	    		if(find_psswd_from_head(i-1,original,hash_searched,psswd_min_length,psswd_max_length,ascii_offset,nbr_chars)==1){ //On dérive la tete de chaine jusqu'a retomber sur le hash recherché
				    fclose(fp);
					free(hash_searched);
   					free(hash_tmp);
   					free(str_password);
		    		return EXIT_SUCCESS;
		    	}
	    	}
   		}
   		//memset(str_password, 0, PSSWD_AREA);
   		memset(str_password, 0, strlen(str_password));
    }
   	printf("No match found ! \n");
   	fclose(fp);
   	free(hash_searched);
   	free(hash_tmp);
   	free(str_password);

	return EXIT_FAILURE;
}
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef FILE_BLOCK_SIZE
    #define FILE_BLOCK_SIZE 8
#endif

/*
 * Compute an xor-based hash of the data provided on STDIN. The result
 * should be placed in the array of length block_size pointed to by
 * hash_val.
 */
char *hash(FILE *f){

	//allocate 64 bit (8 byte) hash for the content of file
	char *hash_val = malloc(sizeof(char)*FILE_BLOCK_SIZE);

	char hash_val_copy[FILE_BLOCK_SIZE];

	//initialize hash_val to be "Empty"
	for(int i = 0; i < FILE_BLOCK_SIZE; i++){
		hash_val_copy[i] = '\0';
	}
	char read_character;
	int hash_index = 0;
	
	//read one character at a time from the file until there are no
	//more characters to read
	while(fread(&read_character, sizeof(char), 1, f) == 1){
		if(hash_index == FILE_BLOCK_SIZE){
			hash_index = 0;
		}

		hash_val_copy[hash_index] = hash_val_copy[hash_index] ^ read_character;
		hash_index++;
	}

	strcpy(hash_val, hash_val_copy);
	return hash_val;
}
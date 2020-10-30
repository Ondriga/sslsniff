/*
 * Source code for ISA project.
 * file: sslsniff.c
 * 
 * (C) Patrik Ondriga (xondri08) 
 */

#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <stdlib.h>
#include <limits.h>

void error_behavior(char* error_message){
	fprintf(stderr, "%s\n", error_message);
	exit(1);
}

// TODO odstran to ak to nebudes potrebovat
/*bool string2int(char* string, int* number){
	if(!strcmp(string, "")){
		return false;
	}
	char* end;
	long int inputNum = strtol(string, &end, 10);
	if(inputNum == LONG_MAX || inputNum == LONG_MIN || strcmp(end, "")){
		return false;
	}
	*number = inputNum;
	return true;
}*/

int main( int argc, char* argv[] )
{
	if(argc != 3){
		error_behavior("Project can be run only with one argument.");
	}
	if(!strcmp(argv[1], "-r")){
		if(!strcmp(argv[2], "")){
			error_behavior("After argument -r must be name of pcapng file.");
		}		
	}else if(!strcmp(argv[1], "-i")){
		int i;
		if(!strcmp(argv[2], "")){
			error_behavior("Network interface can`t be empty string.");
		}
	}else{
		error_behavior("Wrong type of argument, there can be \"-r\" or \"-i\".");
	}
}

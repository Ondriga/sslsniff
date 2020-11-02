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

#include "sslParser.h"

void error_behavior(const char* error_message){
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
		if(strlen(argv[2]) == 0){
			error_behavior("After argument -r must be name of pcapng file.");
		}
		char* error_message;
		error_message = getHandlerOffline(argv[2]);
		if(strlen(error_message) != 0){
			error_behavior(error_message);
		}
	}else if(!strcmp(argv[1], "-i")){
		if(strlen(argv[2]) == 0){
			error_behavior("Network interface can`t be empty string.");
		}
		char* error_message;
		error_message = getHandlerOnline(argv[2]);
		if(strlen(error_message) != 0){
			error_behavior(error_message);
		}
	}else{
		error_behavior("Wrong type of argument, there can be \"-r\" or \"-i\".");
	}
}

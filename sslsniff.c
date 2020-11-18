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
#include "my_ssl.h"

/**
 * Print error message on stderr and end program with code 1.
 * @param error_message String for printing
 */
void error_behavior(const char* error_message){
	fprintf(stderr, "%s\n", error_message);
	exit(1);
}

int main( int argc, char* argv[] )
{
	if(argc == 2){
		if(!strcmp(argv[1], "--help")){
			printf("This program providing ssl sniffing from file or online from interface.\n");
			printf("You can choose source of packets by run program with these arguments:\n");
			printf("		-i [interface name]\n");
			printf("		-r [pcapng file name]\n");
			return 0;
		}
	}
	if(argc != 3){
		error_behavior("Project can be run only with one argument. For help add argument \"--help\"");
	}
	if(!strcmp(argv[1], "-r")){		//Program start with argument -r.
		if(strlen(argv[2]) == 0){	//Check if argument have value.
			error_behavior("After argument -r must be name of pcapng file.");
		}
		//Check if file is readable
		FILE* file = fopen(argv[2], "r");
		if(file == NULL){
			error_behavior("File isn`t exist or can`t be read.");
		}
		fclose(file);
		char* error_message = getHandlerOffline(argv[2]);
		if(strlen(error_message) != 0){
			error_behavior(error_message);
		}
	}else if(!strcmp(argv[1], "-i")){	//Program start with argument -i.
		if(strlen(argv[2]) == 0){	//Check if argument fave value.
			error_behavior("Network interface can`t be empty string.");
		}
		char* error_message = getHandlerOnline(argv[2]);
		if(strlen(error_message) != 0){
			error_behavior(error_message);
		}
	}else{
		error_behavior("Wrong type of argument, there can be \"-r\", \"-i\" or \"--help\".");
	}
}

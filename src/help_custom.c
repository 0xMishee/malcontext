#include <stdio.h>
#include "help_custom.h"



void print_help_pages() {
	printf("\nMalware Context - An analyze tool ");
	printf("\n\n");

	printf("Usage: 									\n");
	printf("  help [-h] [-a] [-p] [-s] [-c] <option>\n");
	printf("										\n\n");

	printf("Options: 																					\n");
	printf("  -h : help				Show this help message and exit										\n");
	printf("  -y : yara-x				Scans a directory or file with .yara rules in yara-x directory	\n");
	printf("  -d : download			Download a malware sample based on the hash							\n");

	api_help();
	download_help();
	search_help();	
	printf("\n\n");



	printf("Additional Information: 	\n");
	printf("  Author: Martin Jakobsson	\n");
	printf("  Version: 0.0.1			\n");
	printf("  License: TBD				\n");
	printf("\n\n");
}

void api_help() {
	printf("APIs: 						\n");
	printf(" -um : unpac_me				\n");
	printf(" -mp : malpedia				\n");
	printf(" -ms : malshare				\n");
	printf(" -ha : hybridanalysis		\n");
}


void download_help() {
	printf("Arguments: \n");
	printf("  -d <API> <hash>: download			Download a malware sample based on the hash\n");
}

void search_help() {
	printf("Arguments: \n");
	printf("  -s <hash>: search			Search for a malware sample based on the hash\n");
}

void yara_help() {
	printf("Not implemented yet\n");

}

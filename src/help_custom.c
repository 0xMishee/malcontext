#include <stdio.h>
#include "help_custom.h"



void print_help_pages() {
	printf("\nMalware Context - A malware triage tool ");

	printf("\n\n");

	printf("Usage: 									  \n");
	printf("  help [-h] [-s] [-d] [-c] <option> <hash>\n");
	printf("										  \n\n");

	printf("Options: 																					\n");
	printf("  -h : help				Show this help message and exit										\n");
	printf("  -d : download			Download a malware sample based on the hash							\n");

	download_help();

	search_help();	

	printf("\n\n");

	printf("Additional Information: 	\n");
	printf("  Author: Martin Jakobsson	\n");
	printf("  Version: 0.1.0			\n");
	printf("  License: GPL-3.0 license	\n");
	printf("\n\n");
}

void download_help() {
	printf("Arguments: 							If no API is specified the default order is used.\n");
	printf("  -d <API> <hash>: download			Download a malware sample based on the hash\n");

	printf("APIs: 						\n");
	printf(" -um : unpac_me				\n");
	printf(" -mp : malpedia				\n");
	printf(" -ms : malshare				Not yet added.\n");
	printf(" -ha : hybridanalysis		Not yet added.\n");
	printf(" -mb : malware bazaar 		Not Yet added.\n");
}

void search_help() {
	printf("Arguments: \n");
	printf("  -s <hash>: search			Search for a malware sample based on the hash.\n");
}

void context_help() {
	printf("Arguments: \n");
	printf("  -c <hash>: context			Analyze the context of the malware sample based on the hash.\n");
}
#include <stdio.h>
#include "help_custom.h"

void print_help_pages() {
	printf("\nMalware Context - A malware triage tool ");

	printf("\n\n");

	printf("Usage:                                      \n");
	printf("  help [-h] [-s] [-d] [-c] <option> <hash>\n");
	printf("                                            \n\n");

	printf("Options:                                                                   		                \n");
	printf("  -h : help                		Show this help message and exit                                 \n");
	printf("  -d : download            		Download a malware sample based on the hash                     \n");
	printf("  -s : search        			Search for a malware sample based on the hash.                  \n");
	printf("  -c : context       			Analyze the context of the malware sample based on the hash.    \n");


	printf("\n\n");

	printf("APIs:                                                                  		                    \n");
	printf(" -um : unpac_me                                                        					        \n");
	printf(" -mp : malpedia                                                           					    \n");
	printf(" -ms : malshare                                          								       	\n");
	printf(" -ha : hybridanalysis                                           							 	\n");
	printf(" -mb : malware bazaar                                           								\n");

	printf("\n\n");

	printf("Additional Information:                                                                  		\n");
	printf("  Author: Martin Jakobsson                                                               		\n");
	printf("  Version: 0.1.0                                                                         		\n");
	printf("  License: GPL-3.0 license                                                               		\n");
	printf("\n\n");
}

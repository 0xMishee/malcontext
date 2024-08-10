#include <stdio.h>
#include "help_custom.h"



void help() {
	printf("\nMalware Context - An analyze tool ");
	printf("\n\n");

	printf("Usage: \n");
	printf("  help [-h] [-a] [-p] [-s] [-c] <option>\n");
	printf("\n\n");

	printf("Options: \n");
	printf("  -h : help				Show this help message and exit\n");
	printf("  -a : active				Listens for interesting events based on configuration and interupts when triggered\n");
	printf("  -p : passive				Same as active but does not interupt any processes\n");
	printf("  -s : scan				Scans a file or directory based on search and configuration parameter\n");
	printf("  -c : configuration			Show the current configuration\n");
	printf("  -y : yara-x				Scans a directory or file with .yara rules in yara-x directory\n");
	printf("\n\n");

	printf("Arguments: \n");
	printf("  input  :				The file or directory to scan\n");	
	printf("  output :				The output file to write the results to\n");
	printf("\n\n");

	active_help();
	passive_help();
	scan_help();
	configuration_help();


	printf("Additional Information: \n");
	printf("  Author: Martin Jakobsson\n");
	printf("  Version: 0.0.1\n");
	printf("  License: TBD\n");
	printf("\n\n");
}

void configuration_help() {
	printf("Configuration Options: \n");
	printf("  -a	: add				Add a new key to the configuration\n");
	printf("  -r	: remove			Remove a key from the configuration\n");
	printf("  -l	: list				List all keys in the configuration\n");
	printf("  -s	: show				Show the current configuration\n");
	printf("  none	: no value			Either shows the current config or initializes a new one if there's none \n");
	printf("\n\n");
}

void active_help() {
	
}

void passive_help() {
	

}

void scan_help() {
	

}


void yara_help() {
	printf("Yara-x Options: \n");
	printf("  -y <dir/file>	 				\n");
	printf("  Example:                  malware_context -y 'C:\\Program Files\\'\n");
	printf("\n\n");

}

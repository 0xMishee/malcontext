#ifndef CONTEXT_H
#define CONTEXT_H

#include <stdio.h>

void context_virustotal_file_print(char* virustotal_json_string);
void context_virustotal_file_behaviour_print(char* virustotal_json_string);
void context_malware_summary(char* sample_hash);

#endif // CONTEXT_H

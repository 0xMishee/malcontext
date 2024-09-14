#ifndef CONFIG_H
#define CONFIG_H

#include <stdio.h>

// Opens the configuration file and returns a string for parsing
char* open_configuration(const char* key_file);
char* get_api_key_value(const char* api_key_name);


#endif // CONFIG_H

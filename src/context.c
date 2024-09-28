#include <stdio.h>

#include "ansi_colours.h"
#include "miscellaneous.h"
#include "malwarebazaar.h"
#include "virustotal.h"
#include "config.h"
#include <cjson/cJSON.h>

// Function to print a summary of the malware, uses virustotal API to get the information.
void context_malware_summary(char* sample_hash){
    char* api_key_virustotal = get_api_key_value("virustotal"); 
    char* virustotal_response = virustotal_sample_availability(api_key_virustotal, sample_hash);
    cJSON* virustotal_json = cJSON_Parse(virustotal_response);

    // Check so the file exists on VirusTotal
    if(strcmp(cJSON_GetArrayItem(virustotal_json,0)->string,"data") == 0){

        /* Data key contains following:
        - id: hash value
        - type: file
        - links: self link
        - attributes: bulk information about the file
        */


        cJSON* data = cJSON_GetArrayItem(virustotal_json, 0);
        cJSON* id = cJSON_GetObjectItem(data, "id");
        cJSON* links = cJSON_GetObjectItem(data, "links");
        cJSON* attributes = cJSON_GetObjectItem(data, "attributes");
        cJSON* pe_info = cJSON_GetObjectItem(attributes, "pe_info");
        cJSON* sections = cJSON_GetObjectItem(pe_info, "sections");
        cJSON* import_list = cJSON_GetObjectItem(pe_info, "import_list");
        cJSON* detect_it_easy = cJSON_GetObjectItem(attributes, "detectiteasy");


        // Don't put to much weight on these.
        printf(ANSI_BOLD_MAGENTA"Malware Summary For "ANSI_RESET "%s : %s\n\n", cJSON_GetObjectItem(attributes, "meaningful_name")->valuestring, id->valuestring);
        printf(ANSI_BOLD_MAGENTA"Link"ANSI_RESET" : %s\n\n", cJSON_GetObjectItem(links, "self")->valuestring);
        printf(ANSI_BOLD_MAGENTA"Last Submission  : "ANSI_RESET "%s\n", convert_time(cJSON_GetObjectItem(attributes, "last_submission_date")->valueint));
        printf(ANSI_BOLD_MAGENTA"First Submission : "ANSI_RESET "%s\n", convert_time(cJSON_GetObjectItem(attributes, "first_submission_date")->valueint));
        printf(ANSI_BOLD_MAGENTA"Last Submission  : "ANSI_RESET"%s\n", convert_time(cJSON_GetObjectItem(attributes, "last_submission_date")->valueint));

        
        printf(ANSI_BOLD_MAGENTA"\nMalicious : "ANSI_RESET "%d, " ANSI_BOLD_MAGENTA"Suspicious : "ANSI_RESET "%d, " 
               ANSI_BOLD_MAGENTA"Undetected : "ANSI_RESET "%d, " ANSI_BOLD_MAGENTA"Harmless : "ANSI_RESET "%d\n",
                                cJSON_GetObjectItem(cJSON_GetObjectItem(attributes, "last_analysis_stats"), "malicious")->valueint,
                                cJSON_GetObjectItem(cJSON_GetObjectItem(attributes, "last_analysis_stats"), "suspicious")->valueint,
                                cJSON_GetObjectItem(cJSON_GetObjectItem(attributes, "last_analysis_stats"), "undetected")->valueint,
                                cJSON_GetObjectItem(cJSON_GetObjectItem(attributes, "last_analysis_stats"), "harmless")->valueint);

        printf("\n");

        printf(ANSI_BOLD_MAGENTA"SHA256 : "ANSI_RESET"%s\n", cJSON_GetObjectItem(attributes, "sha256")->valuestring);
        printf(ANSI_BOLD_MAGENTA"MD5    : "ANSI_RESET"%s\n", cJSON_GetObjectItem(attributes, "md5")->valuestring);
        printf(ANSI_BOLD_MAGENTA"IMP    : "ANSI_RESET"%s\n\n", cJSON_GetObjectItem(pe_info, "imphash")->valuestring);

        // "Good" supplement instead of imported DLL functions; speaking in terms of capabilities.
        printf(ANSI_BOLD_MAGENTA"Tags    : "ANSI_RESET);
        for (size_t i = 0; i < cJSON_GetArraySize(cJSON_GetObjectItem(attributes, "tags")); i++){
            if (i % 7 == 0 && i != 0) {printf("\n");}
            printf("%s, ", cJSON_GetArrayItem(cJSON_GetObjectItem(attributes, "tags"), i)->valuestring);
            if (i == cJSON_GetArraySize(cJSON_GetObjectItem(attributes, "tags")) - 1){
                printf("\n");
            }
        }

        printf(ANSI_BOLD_MAGENTA"PE Info : "ANSI_RESET);
        printf("%s\n\n",cJSON_GetObjectItem(attributes, "magic")->valuestring);

        // Imported libraries, don't care for specific functions if I just want to get a quick idea. 
        if (import_list) {
            printf(ANSI_BOLD_MAGENTA"Imported Libraries : "ANSI_RESET);
            for (size_t i = 0; i < cJSON_GetArraySize(import_list); i++) {
                if (i % 7 == 0 && i != 0) {printf("\n");}
                cJSON* library = cJSON_GetArrayItem(import_list, i);
                printf("%s, ", cJSON_GetObjectItem(library, "library_name")->valuestring);
                if (i == cJSON_GetArraySize(import_list) - 1) {printf("\n\n");}
            }
        }

        //Detect it easy
        if (detect_it_easy) {
            cJSON* values = cJSON_GetObjectItem(detect_it_easy, "values");
            printf(ANSI_BOLD_MAGENTA"Detect it easy\n"ANSI_RESET);
            for (size_t i = 0; i < cJSON_GetArraySize(values); i++) {
                for (size_t j = 0; j < cJSON_GetArraySize(cJSON_GetArrayItem(values, i)); j++) {
                    cJSON* item = cJSON_GetArrayItem(cJSON_GetArrayItem(values, i), j);
                    printf(ANSI_BOLD_MAGENTA"%s: "ANSI_RESET"%s\n", item->string, item->valuestring);
                };
                printf("\n");
            };
        }

        // Rare that I would need to know the specific sections from the start, but it's nice to have.
        if (sections) {
            printf(ANSI_BOLD_MAGENTA"%-9s %-16s %-9s %-15s %-9s %s\n"ANSI_RESET, "Name", "Virtual Address", "Entropy", "Virtual Size", "Raw Size", "MD5");
            for (size_t i = 0; i < cJSON_GetArraySize(sections); i++) {
                cJSON* section = cJSON_GetArrayItem(sections, i);
                printf("%-10s" , cJSON_GetObjectItem(section, "name")->valuestring);
                printf("%-17d" , cJSON_GetObjectItem(section, "virtual_address")->valueint);
                printf("%-10.2f" , cJSON_GetObjectItem(section, "entropy")->valuedouble);
                printf("%-16d" , cJSON_GetObjectItem(section, "virtual_size")->valueint);
                printf("%-10d" , cJSON_GetObjectItem(section, "raw_size")->valueint);
                printf("%s\n" , cJSON_GetObjectItem(section, "md5")->valuestring);

                if (i == cJSON_GetArraySize(sections) - 1) {printf("\n\n");}   
            }
        }   



        cJSON_Delete(data);
        cJSON_Delete(id);
        cJSON_Delete(links);
        cJSON_Delete(attributes);
        cJSON_Delete(pe_info);
        cJSON_Delete(sections);
        cJSON_Delete(import_list);
        cJSON_Delete(detect_it_easy);

        goto _END_OF_FUNC;

    } else if (!virustotal_json){
        printf(ANSI_RED"[!] Error: Virustotal API returned an error\n"ANSI_RESET);
        goto _END_OF_FUNC;
    }
    else {
        goto _END_OF_FUNC;
    }

    _END_OF_FUNC:
    free(api_key_virustotal);
    free(virustotal_response);
    cJSON_Delete(virustotal_json);
    return;
};
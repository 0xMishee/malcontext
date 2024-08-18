#include <stdio.h>
#include <time.h>

char* convert_time (int timestamp) {
    time_t time = timestamp;
    struct tm *timeinfo;
    static char buffer[20]; 
    timeinfo = localtime(&time);
    strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", timeinfo);

    if(timeinfo->tm_year == 70){
        char* error = "No date available";
        return error;
    };

    return buffer;
}
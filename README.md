## About 
There's just too many tools for malware analysis, so I decided to pollute the waters and add another one written in C. 

aaand I got bored and needed a project []~(￣▽￣)~*

This tool aims to:
    1. Incorporate APIs from services that I commonly use (VT,Unpacme, Malshare etc).
    2. Summarize data and functionality from these platforms.
    3. Have a "monkey have hash||IP||domain, monkey want data" sort of approach to how complex the tool is to use.
    4. Add YARA-X and AOB Scanner.
    5. Incorporate windows event tracing events for targeted processes.


## Current Version
Version 0.0.1.x:
```
This version: 
- No stable way of using it; but it won't crash (ง •_•)ง
```

## Installation
It's using cmake so you do you (～￣▽￣)～ Still very, very early in development so it's barebones atm.
```
mkdir build
cd build
cmake ..
cmake --build .
```
## Examples
## Roadmap
    1. Add Virustotal API functionality.
    2. Add UnpacME API functionality. 
    3. Add Malshare API functionality.
    4. Add Hash search functionality.
    5. Add Yara-X functionality.
    6. ...more stuff. 
    7. Refactor into assembly (●'◡'●)

## Authors

Me, myself and I. 


#pragma once

#ifndef ANSI_COLOURS_H
#define ANSI_COLOURS_H

// ANSI colour codes for terminal output.
// Easier than to just have it spread out everywhere.＼（〇_ｏ）／

#define ANSI_RED "\x1b[31m" // Errors, fails, missing, offline etc...
#define ANSI_GREEN "\x1b[32m"
#define ANSI_YELLOW "\x1b[33m"
#define ANSI_RESET "\x1b[0m"
#define ANSI_BLUE "\x1b[0;34m" //Title colour

// Bold colours for headers, titles, etc...
#define ANSI_BOLD_GRAY "\x1b[1;30m" // Contextualizing, headers, etc...
#define ANSI_BOLD_BLUE "\x1b[1;34m" // Section headers
#define ANSI_BOLD_GREEN "\x1b[1;32m" // Sub-section headers
#define ANSI_BOLD_YELLOW "\x1b[1;33m" // Result 

#endif // ANSI_COLOURS_H
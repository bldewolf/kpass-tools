/*
    kpass-tools, a command line client  for munging KeePass 1.x format files
    Copyright (C) 2010 Brian De Wolf

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <sys/mman.h>
#include <stdio.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <termios.h>
#include <string.h>
#include <libgen.h>

#include <kpass.h>

#include "lib/getpass.h"
#include "lib/yesno.h"

#include "util.h"

#include "config.h"

static void print_help() {
	puts("kpass-tools - command-line utility for managing KeePass 1.x databases.\n\
Usage: <mode> <mode options>\n\
Available modes:\n\
    list      list contents of a database\n\
    copy      copy entries of a database to another\n\
    merge     merge entries of a database to another\n\
    help      display this\n\
    version   print the version\n\
\n\
See -h in each mode for mode-specific options.");
}


int main(int argc, char* argv[]) {
	if(argc < 2) {
		puts("Missing first argument.\n");
		print_help();
	} else if(!strcmp(argv[1], "list")) {
		argv[1] = argv[0];
		return list_main(argc - 1, argv + 1);
	} else if(!strcmp(argv[1], "copy")) {
		argv[1] = argv[0];
		return copy_main(argc - 1, argv + 1);
	} else if(!strcmp(argv[1], "merge")) {
		argv[1] = argv[0];
		return merge_main(argc - 1, argv + 1);
	} else if(!strcmp(argv[1], "help")) {
		print_help();
	} else if(!strcmp(argv[1], "version")) {
		puts(VERSION);
	} else {
		puts("Unknown mode.\n");
		print_help();
	}

	return 0;
}

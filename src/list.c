/*
    clkpass, a command line client  for munging KeePass 1.x format files
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <kpass.h>

#include "util.h"

static void print_help() {
	puts("kputil list - list contents of a database\n\
Usage: kputil list <options> <files>\n\
Available options:\n\
    -h    displays help");
}

int list_main(int argc, char* argv[]) {
	kpass_db *db;
	uint8_t pw_hash[32];
	char* dest;
	char* pw = NULL;
	int i;
	int mod = 0;
	char c;
	kpass_retval retval;

	while((c = getopt(argc, argv, "hp:")) != -1) {
		switch(c) {
			case 'h':
				print_help();
				return 0;
			case 'p':
				pw = optarg;
				break;
			case '?':
				if(optopt == 'p') {
					fprintf(stderr, "Option p requires an argument\n");
					return 1;
				} else {
					fprintf(stderr, "Unknown option `-%c'.\n", optopt);
					return 1;
				}
			default:
				fprintf(stderr, "HOW DID I GET HERE\n");
				return 1;

		}
	}

	if(optind == argc) {
		fprintf(stderr, "No file specified.\n");
		return 1;
	}

	if(pw) {
		retval = kpass_hash_pw(NULL, pw, pw_hash);
		if(retval) {
			fprintf(stderr, "Failed to hash password: %s\n", kpass_error_str[retval]);
			return retval;
		}

		db = open_db(argv[optind], pw_hash);
	} else {
		if(open_file(argv[optind], &db, pw_hash, 3)) {
			fprintf(stderr, "Open file failed\n");
			return 1;
		}
	}

	if(!db)
		return 1;

	for(i = 0; i < db->entries_len; i++) {
		if(is_metadata(db->entries[i]))
			continue;

		print_entry(db->entries[i]);
	}

	return 0;
}

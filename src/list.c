/*
    kpass-tools, a command line tool for munging KeePass 1.x format files
    Copyright (C) 2013 Brian De Wolf

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
	puts("kpass-tools list - list contents of a database\n\
Usage: kpass-tools list <options> <files>\n\
Available options:\n\
    -e        show only entries\n\
    -g        show only groups\n\
    -E <mask> this mask restricts which fields are printed for entries\n\
    -G <mask> this mask restricts which fields are printed for groups\n\
    -b        brief output (sets brief group and entry masks)\n\
    -m        show metadata elements (hidden by default)\n\
    -n        show fields as numeric values rather than pretty strings\n\
    -p <pw>   the password to unlock the database (taken interactively by default)\n\
    -s        sorts entries by UUID before printing\n\
    -h        this displays the help");
}

int list_main(int argc, char* argv[]) {
	kpass_db *db;
	uint8_t pw_hash[32];
	char* pw = NULL;
	uint32_t i;
	int dbind;
	char c;
	int numeric = 0;
	int metadata = 0;
	int entry_mask = -1;
	int group_mask = -1;
	int show_only = 0;
	int sort_entries = 0;
	int num_dbs;

	while((c = getopt(argc, argv, "egE:G:bmnp:sh")) != -1) {
		switch(c) {
			case 'e':
				show_only = c;
				break;
			case 'g':
				show_only = c;
				break;
			case 'E':
				entry_mask = atoi(optarg);
				if(!entry_mask) {
					fprintf(stderr, "Entry mask must be non-zero.\n");
					return 1;
				}
				break;
			case 'G':
				group_mask = atoi(optarg);
				if(!group_mask) {
					fprintf(stderr, "Group mask must be non-zero.\n");
					return 1;
				}
				break;
			case 'b':
				entry_mask = BRIEF_ENTRY_MASK;
				group_mask = BRIEF_GROUP_MASK;
				break;
			case 'm':
				metadata = 1;
				break;
			case 'n':
				numeric = 1;
				break;
			case 'p':
				pw = optarg;
				break;
			case 's':
				sort_entries = 1;
				break;
			case 'h':
				print_help();
				return 0;
			case '?':
				return 1;
			default:
				fprintf(stderr, "HOW DID I GET HERE\n");
				return 1;

		}
	}

	if(optind == argc) {
		fprintf(stderr, "No file specified.\n");
		return 1;
	}

	num_dbs = argc - optind;
	for(dbind = optind; dbind < argc; dbind++) {
		if(open_file(argv[dbind], &db, pw, pw_hash, 3)) {
			fprintf(stderr, "Open file failed\n");
			return 1;
		}

		if(!db)
			return 1;

		if(num_dbs > 1 )
			printf("Database: %s\n", argv[dbind]);

		if(show_only == 0 || show_only == 'g') {
			puts("Groups:");

			for(i = 0; i < db->groups_len; i++) {
				print_group(db->groups[i], group_mask, numeric);
			}
		}

		if(show_only == 0 || show_only == 'e') {
			puts("Entries:");

			if(sort_entries)
				qsort(db->entries, db->entries_len,
					sizeof(*db->entries), qsort_entry);

			for(i = 0; i < db->entries_len; i++) {
				if(!metadata && is_metadata(db->entries[i]))
					continue;

				print_entry(db->entries[i], entry_mask, numeric);
			}
		}
	}

	return 0;
}

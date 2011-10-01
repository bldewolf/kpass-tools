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
	puts("kputil copy - copy entries of a database to another\n\
Usage: kputil copy <options> <UUIDs>\n\
Available options:\n\
    -s        source database\n\
    -d        destination database\n\
    -o        output database (if not specified, we clobber the destination)\n\
    -p <pw>   the password to unlock the databases (interactive otherwise)\n\
              If -P is in effect, this password is used on the first database\n\
    -P <UUID> the UUID from the source database to use as the password for\n\
              the destination database\n\
    -r        reverses the order the databases are opened and causes -P to\n\
              read from the destination database rather than the source\n\
    -h        this displays the help");
}

int copy_main(int argc, char* argv[]) {
	kpass_db *ddb, *sdb, **db;
	uint8_t pw_hash[32];
	char* path;
	char* pw = NULL;
	char* pw_uuid = NULL;
	int reverse = 0;
	int i;
	int mod = 0;
	int dbind;
	char c;
	kpass_retval retval;
	char *src, *dst, *out;

	while((c = getopt(argc, argv, "d:s:hp:P:o:r")) != -1) {
		switch(c) {
			case 'd':
				dst = optarg;
				break;
			case 's':
				src = optarg;
				break;
			case 'h':
				print_help();
				return 0;
			case 'p':
				pw = optarg;
				break;
			case 'P':
				pw_uuid = optarg;
				break;
			case 'o':
				out = optarg;
				break;
			case 'r':
				reverse = !reverse;
				break;
			case '?':
				if(optopt == 'p' || optopt == 's' || optopt == 'd' || optopt == 'P' || optopt == 'o') {
//					getopt prints an error here already
//					fprintf(stderr, "Option %c requires an argument\n", optopt);
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
		fprintf(stderr, "No UUIDs specified.\n");
		return 1;
	}

//	Use pointer magic to accomodate reversed order in the case of using pw_uuid
	if(!reverse) {
		path = src;
		db = &sdb;
	} else {
		path = dst;
		db = &ddb;
	}

	if(open_file(path, db, pw, pw_hash, 3)) {
		fprintf(stderr, "Open file \"%s\" failed\n", path);
		return 1;
	}

	if(reverse) {
		path = src;
		db = &sdb;
	} else {
		path = dst;
		db = &ddb;
	}

//	find pw_uuid and replace pw with it
	if(open_file(path, db, pw, pw_hash, 3)) {
		fprintf(stderr, "Open file \"%s\" failed\n", path);
		return 1;
	}

	return 0;
}

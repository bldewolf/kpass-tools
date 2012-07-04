/*
    kpass-tools, a collection of tools for munging KeePass 1.x format files
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

#include <uuid/uuid.h>

#include <kpass.h>

#include "util.h"

static void print_help() {
	puts("kputil copy - copy entries of a database to another\n\
Usage: kputil copy <options> <UUIDs>\n\
Available options:\n\
    -s        source database\n\
    -d        destination database\n\
    -o        output database (currently too timid to clobber)\n\
    -p <pw>   the password to unlock the databases (interactive otherwise)\n\
              If -P is set, this password is used on the first database\n\
    -P <UUID> the UUID from the source database to use as the password for\n\
              the destination database\n\
    -r        reverses the order the databases are opened and causes -P to\n\
              read from the destination database rather than the source\n\
    -h        this displays the help");
}

int copy_main(int argc, char* argv[]) {
	kpass_db *ddb = NULL, *sdb = NULL, **db;
	uint8_t spwh[32];
	uint8_t dpwh[32];
	uint8_t *pwh;
	char* path;
	char* pw = NULL;
	char* pw_uuid = NULL;
	int reverse = 0;
	char c;
	char *src, *dst, *out;
	kpass_entry *e;
	uuid_t uuid;
	int copied = 0;

	while((c = getopt(argc, argv, "d:s:hp:P:o:r")) != -1) {
		switch(c) {
			case 's':
				src = optarg;
				break;
			case 'd':
				dst = optarg;
				break;
			case 'o':
				out = optarg;
				break;
			case 'p':
				pw = optarg;
				break;
			case 'P':
				pw_uuid = optarg;
				break;
			case 'r':
				reverse = !reverse;
				break;
			case 'h':
				print_help();
				return 0;
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
	if(!src) {
		fprintf(stderr, "No source specified.\n");
		return 1;
	}
	if(!dst) {
		fprintf(stderr, "No destination specified.\n");
		return 1;
	}
	if(!out) {
		fprintf(stderr, "No output specified.\n");
		return 1;
	}

//	Use pointer magic to accomodate reversed order in the case of using pw_uuid
	if(!reverse) {
		path = src;
		db = &sdb;
		pwh = spwh;
	} else {
		path = dst;
		db = &ddb;
		pwh = dpwh;
	}

	if(open_file(path, db, pw, pwh, 3)) {
		fprintf(stderr, "Open file %s failed\n", path);
		goto copy_failed;
	}

//	find pw_uuid and replace pw with it
	if(pw_uuid) {
		if(uuid_parse(pw_uuid, uuid)) {
			fprintf(stderr, "Failed to parse UUID %s for second database password\n", pw_uuid);
			goto copy_failed;
		}
		e = find_entry_ptr_uuid(*db, uuid);
		if(!e) {
			fprintf(stderr, "No entry found for UUID %s in %s for second database password\n", pw_uuid, path);
			goto copy_failed;
		}
		pw = e->password;
	}

//	More magic
	if(reverse) {
		path = src;
		db = &sdb;
		pwh = spwh;
	} else {
		path = dst;
		db = &ddb;
		pwh = dpwh;
	}

	if(open_file(path, db, pw, pwh, 3)) {
		fprintf(stderr, "Open file %s failed\n", path);
		goto copy_failed;
	}

//	Do the actual copying
	for(; optind < argc; optind++) {
		if(uuid_parse(argv[optind], uuid)) {
			fprintf(stderr, "Failed to parse UUID %s for copying\n", argv[optind]);
			goto copy_failed;
		}
		if(find_entry_index_uuid(ddb, uuid) != -1) {
			fprintf(stderr, "UUID %s already exists in %s\n", argv[optind], dst);
			goto copy_failed;
		}

		e = remove_entry(sdb, uuid);
		if(!e) {
			fprintf(stderr, "No entry found for UUID %s in %s\n", argv[optind], src);
			goto copy_failed;
		}
		insert_entry(ddb, e);
		copied++;
	}
	if(copied) {
		save_db(out, ddb, dpwh);
		printf("%d entries were copied.\n", copied);
	} else {
		puts("No entries were copied");
	}

	kpass_free_db(sdb);
	free(sdb);
	kpass_free_db(ddb);
	free(ddb);

	return 0;

copy_failed:
	if(sdb) {
		kpass_free_db(sdb);
		free(sdb);
	}
	if(ddb) {
		kpass_free_db(ddb);
		free(ddb);
	}
	return 1;
}

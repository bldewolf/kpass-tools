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

kpass_db* open_db(char *filename, uint8_t *pw_hash) {
	uint8_t *file = NULL;
	int length;
	int fd;
	struct stat sb;
	kpass_db *db;
	kpass_retval retval;

	fd = open(filename, O_RDONLY);
	if(fd == -1) {
		printf("open of \"%s\" failed: %m\n", filename);
		return NULL;
	}

	if(fstat(fd, &sb) == -1) {
		printf("fstat of \"%s\" failed: %m\n", filename);
		close(fd);
		return NULL;
	}

	length = sb.st_size;

	file = mmap(NULL, length, PROT_READ, MAP_SHARED, fd, 0);
	if(file == MAP_FAILED) {
		printf("mmap of \"%s\" failed: %m\n", filename);
		close(fd);
		return NULL;
	}

	db = malloc(sizeof(kpass_db));
	retval = kpass_init_db(db, file, length);
	if(retval) {
		printf("init of \"%s\" failed: %s\n", filename, kpass_error_str[retval]);
		munmap(file, length);
		close(fd);
		return NULL;
	}
	
	retval = kpass_decrypt_db(db, pw_hash);
	if(retval) {
		printf("decrypt of \"%s\" failed: %s\n", filename, kpass_error_str[retval]);
		munmap(file, length);
		close(fd);
		return NULL;
	}

	munmap(file, length);
	close(fd);
	return db;
}

void fix_group(kpass_db *db, int i) {
	db->entries[i]->group_id = db->groups[0]->id;
}

// date controls whether we compare mtime
int compare_entry(kpass_entry *a, kpass_entry *b, int date) {
	int res;
	struct tm atm, btm;
	time_t atime, btime;

	// If the UUIDs don't match, return the difference
	res = compare_entry_field(kpass_entry_uuid, a, b);
	if(!date || res)
		return res;
	
	return compare_entry_field(kpass_entry_mtime, a, b);
}

int qsort_entry(const void *a, const void *b) {
	return compare_entry(*(kpass_entry * const *) a,
			*(kpass_entry * const *) b, 0);
}

kpass_retval open_file(char* filename, kpass_db **db, uint8_t pw_hash[32], int tries) {
	char *password;
	char *prompt;
	char *bn = basename(filename);
	char *fmt = "Password for \"%s\":";
	int plen = snprintf(NULL, 0, fmt, bn) + 1;
	int i = 0;
	kpass_retval retval;

	prompt = malloc(plen);

	snprintf(prompt, plen + 1, fmt, bn);

	for(i = 0; i < tries; i++) {
		password = getpass(prompt);
//		password = "test";

		retval = kpass_hash_pw(*db, password, pw_hash);
		if(retval) {
			printf("hash of \"%s\" failed: %s\n", filename, kpass_error_str[retval]);
			return retval;
		}

		memset(password, 0, strlen(password));

		*db = open_db(filename, pw_hash);

		if(*db) // open successful
			break;
	}
	free(prompt);

	return 0;
}

int save_db(char* filename, kpass_db* db, uint8_t* pw_hash) {
	int fd, size, out;
	char* buf;
	kpass_retval retval;

	size = kpass_db_encrypted_len(db);

	buf = malloc(size);

	retval = kpass_encrypt_db(db, pw_hash, buf);
	if(retval) {
		printf("encrypt of \"%s\" failed: %s\n", filename, kpass_error_str[retval]);
		free(buf);
		return retval;
	}

	fd = open(filename, O_RDWR | O_CREAT | O_TRUNC, 0777);
	if(fd < 0) {
		printf("open of \"%s\" failed: %m\n", filename);
		free(buf);
		return -1;
	}
	
	out = write(fd, buf, size);
	if(out < size) {
		if( out == -1)
			printf("write of \"%s\" failed: %m\n", filename);
		else
			printf("write of \"%s\" failed: not enough bytes written\n", filename);
		free(buf);
		close(fd);
		return -1;
	}

	out = close(fd);
	if(out == -1) {
		printf("close of \"%s\" failed: %m\n", filename);
		free(buf);
		return -1;
	}

	free(buf);
	return 0;
}

int main(int argc, char* argv[]) {
	kpass_db *dbs[2];
	uint8_t pw_hash[2][32];
	char* dest;
	int i;
	int mod = 0;

	int target, source;

	if(argc != 3) return 1;

	if(open_file(argv[1], &dbs[0], pw_hash[0], 3) ||
		open_file(argv[2], &dbs[1], pw_hash[1], 3)) {
		printf("Open file failed somehow\n");
	}

	if(!dbs[0] && !dbs[1])
		return 1;

	source = 0;
	target = 1;

	printf("qsorting\n");

	qsort(dbs[source]->entries, dbs[source]->entries_len,
		sizeof(*dbs[source]->entries), qsort_entry);
		
	printf("Searching for dups\n");

	for(i = 0; i < dbs[target]->entries_len; i++) {
		kpass_entry **br, *source_e, *target_e, *tmp;
		char c;
		int source_i;

		if(is_metadata(dbs[target]->entries[i]))
			continue;

		target_e = dbs[target]->entries[i];

//		printf("Searching for entry:\n");
//		print_entry(dbs[target]->entries[i]);

		br = bsearch(&target_e, dbs[source]->entries,
			dbs[source]->entries_len, sizeof(*dbs[source]->entries),
			qsort_entry);
		if(br) {
			source_e = *br;
		} else {
			source_e = NULL;
		}


		if(source_e && compare_entry(source_e, target_e, 1) > 0) {
			printf("The following differences were found:\n");
			print_entry_diff(target_e, source_e);

			printf("Replace entry? (yes/no) ");
			if(yesno()) {
				mod = 1;
				printf("Swapping entries...\n");
				source_i = find_entry_index_ptr(dbs[source], source_e);
				tmp = dbs[source]->entries[source_i];
				dbs[source]->entries[source_i] = target_e;
				dbs[target]->entries[i] = tmp;

				if(find_group_index_id(dbs[target], tmp->group_id) == -1) {
					printf("Entry group ID not found, setting to first listed group.\n");
					fix_group(dbs[target], i);
				}
			} else {
				printf("Skipping...\n");
			}
		}
	}

	printf("Okay finished\n");
/*	for(i = 0; i < dbs[target]->entries_len; i++) {
		if(is_metadata(dbs[target]->entries[i]))
			continue;
		print_entry(dbs[target]->entries[i]);
	}*/

	if(mod) {
		dest = malloc(strlen(argv[target]) + 5);
		strcpy(dest, argv[target]);
		strcat(dest, ".new");
		printf("Saving modified DB to %s\n", dest);

		save_db(dest, dbs[target], pw_hash[target]);
		free(dest);
	} else {
		printf("No changes found, not bothering saving.\n");
	}

	return 0;
}

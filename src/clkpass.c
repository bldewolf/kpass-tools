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
#include <unistd.h>
#include <string.h>
#include <uuid/uuid.h>
#include <libgen.h>

#include <kpass.h>


kpass_db* open_db(char *filename, char *password) {
	uint8_t *file = NULL;
	int length;
	int fd;
	char pw_hash[32];
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

	retval = kpass_hash_pw(db, password, pw_hash);
	if(retval) {
		printf("hash of \"%s\" failed: %s\n", filename, kpass_error_str[retval]);
		munmap(file, length);
		close(fd);
		return NULL;
	}
	if(retval) exit(retval);

	
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


int main(int argc, char* argv[]) {
	int dbs_len = 10;
	kpass_db **dbs = malloc(dbs_len * sizeof(*dbs));
	int dbs_used = 0;

	int i;

	if(argc < 2) return 1;

	for(i = 1; i < argc; i++) {
		char *password;
		kpass_db *next;
		char *prompt;
		char *bn = basename(argv[i]);
		char *fmt = "Password for \"%s\":";
		int plen = snprintf(NULL, 0, fmt, bn) + 1;

//		printf("Working on %s\n", argv[i]);

		prompt = malloc(plen);

		snprintf(prompt, plen + 1, fmt, bn);

		password = getpass(prompt);

		next = open_db(argv[i], password);
		if(next) {
			if(dbs_len == dbs_used) {
				dbs_len += 10;
				dbs = realloc(dbs, dbs_len);
			}
			dbs[dbs_used] = next;
			dbs_used++;
		}

		free(prompt);
	}

	return 0;
}

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



/* These are helper functions that I might eventually merge into libkpass */

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

#define BIT_SET(x, n) ((1 << ((n) - 1)) & (x))

char *entry_field_names[kpass_entry_num_types] = {
	"comment",
	"UUID",
	"group ID",
	"image ID",
	"title",
	"URL",
	"username",
	"password",
	"notes",
	"creation time",
	"last modification time",
	"last access time",
	"expiration time",
	"binary description",
	"binary data",
	};

char *group_field_names[kpass_group_num_types] = {
	"comment",
	"ID",
	"name",
	"creation time",
	"last modification time",
	"last access time",
	"expiration time",
	"image ID",
	"level",
	"flags",
	};

kpass_retval open_db(char *filename, uint8_t *pw_hash, kpass_db **db) {
	uint8_t *file = NULL;
	int length;
	int fd;
	struct stat sb;
	kpass_retval retval;

	fd = open(filename, O_RDONLY);
	if(fd == -1) {
		printf("open of \"%s\" failed: %m\n", filename);
		return -1;
	}

	if(fstat(fd, &sb) == -1) {
		printf("fstat of \"%s\" failed: %m\n", filename);
		close(fd);
		return -1;
	}

	length = sb.st_size;

	file = mmap(NULL, length, PROT_READ, MAP_SHARED, fd, 0);
	if(file == MAP_FAILED) {
		printf("mmap of \"%s\" failed: %m\n", filename);
		close(fd);
		return -1;
	}

	*db = malloc(sizeof(kpass_db));
	retval = kpass_init_db(*db, file, length);
	if(retval) {
		printf("init of \"%s\" failed: %s\n", filename, kpass_strerror(retval));
		free(*db);
		*db = NULL;
		munmap(file, length);
		close(fd);
		return retval;
	}

	retval = kpass_decrypt_db(*db, pw_hash);
	if(retval) {
		printf("decrypt of \"%s\" failed: %s\n", filename, kpass_strerror(retval));
		free(*db);
		*db = NULL;
		munmap(file, length);
		close(fd);
		return retval;
	}

	munmap(file, length);
	close(fd);
	return 0;
}

// date controls whether we compare mtime
int compare_entry(kpass_entry *a, kpass_entry *b, int date) {
	int res;

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

kpass_retval open_file(char* filename, kpass_db **db, char* pw, uint8_t pw_hash[32], int tries) {
	kpass_retval retval = -1;
	if(!pw) {
		return open_file_interactive(filename, db, pw_hash, tries);
	}

	kpass_hash_pw(pw, pw_hash);
	return open_db(filename, pw_hash, db);
}


kpass_retval open_file_interactive(char* filename, kpass_db **db, uint8_t pw_hash[32], int tries) {
	char *password;
	char *prompt;
	char *bn = basename(filename);
	char *fmt = "Password for \"%s\":";
	int plen = snprintf(NULL, 0, fmt, bn) + 1;
	int i = 0;
	int retval;

	prompt = malloc(plen);

	snprintf(prompt, plen + 1, fmt, bn);

	for(i = 0; i < tries; i++) {
		password = getpass(prompt);

		kpass_hash_pw(password, pw_hash);

		memset(password, 0, strlen(password));

		retval = open_db(filename, pw_hash, db);

		if(!retval || retval == -1) // open successful or received non-kpass error
			break;
	}
	free(prompt);

	return retval;
}

int save_db(char* filename, kpass_db* db, uint8_t* pw_hash) {
	int fd, size, out;
	unsigned char* buf;
	int retval;

	size = kpass_db_encrypted_len(db);

	buf = malloc(size);

	retval = kpass_encrypt_db(db, pw_hash, buf);
	if(retval) {
		printf("encrypt of \"%s\" failed: %s\n", filename, kpass_strerror(retval));
		free(buf);
		return retval;
	}

	fd = open(filename, O_RDWR | O_CREAT | O_TRUNC, 0666);
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

void fix_group(kpass_db *db, int i) {
	db->entries[i]->group_id = db->groups[0]->id;
}

int is_metadata(kpass_entry *e) {
	return	e->data_len &&
		e->desc && !strcmp(e->desc, "bin-stream") &&
		e->title && !strcmp(e->title, "Meta-Info") && 
		e->username && !strcmp(e->username, "SYSTEM") &&
		e->url && !strcmp(e->url, "$") &&
		!e->image_id;
}

int entry_field_strn(kpass_entry *e, kpass_entry_type t, char *str, int n) {
	char uuid[37];
	struct tm tms;
	switch(t) {
		case kpass_entry_uuid:
			uuid_unparse(e->uuid, uuid);
			strncpy(str, uuid, n);
			return 0;
		case kpass_entry_group_id:
			snprintf(str, n, "%u", e->group_id);
			return 0;
		case kpass_entry_image_id:
			snprintf(str, n, "%u", e->image_id);
			return 0;
		case kpass_entry_title:
			strncpy(str, e->title, n);
			return 0;
		case kpass_entry_url:
			strncpy(str, e->url, n);
			return 0;
		case kpass_entry_username:
			strncpy(str, e->username, n);
			return 0;
		case kpass_entry_password:
			strncpy(str, e->password, n);
			return 0;
		case kpass_entry_notes:
			strncpy(str, e->notes, n);
			return 0;
		case kpass_entry_ctime:
			memset(&tms, 0, sizeof(tms));
			kpass_unpack_time(e->ctime, &tms);
			strftime(str, n, "%Y-%m-%d %H:%M:%S", &tms);
			return 0;
		case kpass_entry_mtime:
			memset(&tms, 0, sizeof(tms));
			kpass_unpack_time(e->mtime, &tms);
			strftime(str, n, "%Y-%m-%d %H:%M:%S", &tms);
			return 0;
		case kpass_entry_atime:
			memset(&tms, 0, sizeof(tms));
			kpass_unpack_time(e->atime, &tms);
			strftime(str, n, "%Y-%m-%d %H:%M:%S", &tms);
			return 0;
		case kpass_entry_etime:
			memset(&tms, 0, sizeof(tms));
			kpass_unpack_time(e->etime, &tms);
			strftime(str, n, "%Y-%m-%d %H:%M:%S", &tms);
			return 0;
		case kpass_entry_desc:
			strncpy(str, e->desc, n);
			return 0;
		case kpass_entry_data:
			return 1;
		default:
			return 1;
	}
}

int group_field_strn(kpass_group *g, kpass_group_type t, char *str, int n) {
	struct tm tms;
	switch(t) {
		case kpass_group_id:
			snprintf(str, n, "%u", g->id);
			return 0;
		case kpass_group_name:
			strncpy(str, g->name, n);
			return 0;
		case kpass_group_ctime:
			memset(&tms, 0, sizeof(tms));
			kpass_unpack_time(g->ctime, &tms);
			strftime(str, n, "%Y-%m-%d %H:%M:%S", &tms);
			return 0;
		case kpass_group_mtime:
			memset(&tms, 0, sizeof(tms));
			kpass_unpack_time(g->mtime, &tms);
			strftime(str, n, "%Y-%m-%d %H:%M:%S", &tms);
			return 0;
		case kpass_group_atime:
			memset(&tms, 0, sizeof(tms));
			kpass_unpack_time(g->atime, &tms);
			strftime(str, n, "%Y-%m-%d %H:%M:%S", &tms);
			return 0;
		case kpass_group_etime:
			memset(&tms, 0, sizeof(tms));
			kpass_unpack_time(g->etime, &tms);
			strftime(str, n, "%Y-%m-%d %H:%M:%S", &tms);
			return 0;
		case kpass_group_image_id:
			snprintf(str, n, "%u", g->image_id);
			return 0;
		case kpass_group_level:
			snprintf(str, n, "%hu", g->level);
			return 0;
		case kpass_group_flags:
			snprintf(str, n, "%u", g->flags);
			return 0;
		default:
			return 1;
	}
}

void print_entry(kpass_entry *e, int mask, int numeric) {
	char tmp[60];
	kpass_entry_type i;

	for(i = 1; i < kpass_entry_num_types; i++) {
		if(!BIT_SET(mask, i))
			continue;
		int ret = entry_field_strn(e, i, tmp, 60);
		if(ret) continue;
		if(numeric) {
			printf("%d: %s\n", i, tmp);
		} else {
			printf("%s: %s\n", entry_field_names[i], tmp);
		}
	}
}

void print_group(kpass_group *g, int mask, int numeric) {
	char tmp[60];
	kpass_group_type i;

	for(i = 1; i < kpass_group_num_types; i++) {
		if(!BIT_SET(mask, i))
			continue;
		int ret = group_field_strn(g, i, tmp, 60);
		if(ret) continue;
		if(numeric) {
			printf("%d: %s\n", i, tmp);
		} else {
			printf("%s: %s\n", group_field_names[i], tmp);
		}
	}
}

int compare_entry_field(kpass_entry_type t, kpass_entry *a, kpass_entry *b) {
	struct tm atm, btm;
	time_t atime, btime;

	switch(t) {
		case kpass_entry_uuid:
			return uuid_compare(a->uuid, b->uuid);
		case kpass_entry_group_id:
			return a->group_id - b->group_id;
		case kpass_entry_image_id:
			return a->image_id - b->image_id;
		case kpass_entry_title:
			return strcmp(a->title, b->title);
		case kpass_entry_url:
			return strcmp(a->url, b->url);
		case kpass_entry_username:
			return strcmp(a->username, b->username);
		case kpass_entry_password:
			return strcmp(a->password, b->password);
		case kpass_entry_notes:
			return strcmp(a->notes, b->notes);
		case kpass_entry_ctime:
			memset(&atm, 0, sizeof(atm));
			memset(&btm, 0, sizeof(btm));
			kpass_unpack_time(a->ctime, &atm);
			kpass_unpack_time(b->ctime, &btm);

			atime = mktime(&atm);
			btime = mktime(&btm);

			return atime - btime;
		case kpass_entry_mtime:
			memset(&atm, 0, sizeof(atm));
			memset(&btm, 0, sizeof(btm));
			kpass_unpack_time(a->mtime, &atm);
			kpass_unpack_time(b->mtime, &btm);

			atime = mktime(&atm);
			btime = mktime(&btm);

			return atime - btime;
		case kpass_entry_atime:
			memset(&atm, 0, sizeof(atm));
			memset(&btm, 0, sizeof(btm));
			kpass_unpack_time(a->atime, &atm);
			kpass_unpack_time(b->atime, &btm);

			atime = mktime(&atm);
			btime = mktime(&btm);

			return atime - btime;
		case kpass_entry_etime:
			memset(&atm, 0, sizeof(atm));
			memset(&btm, 0, sizeof(btm));
			kpass_unpack_time(a->etime, &atm);
			kpass_unpack_time(b->etime, &btm);

			atime = mktime(&atm);
			btime = mktime(&btm);

			return atime - btime;
		case kpass_entry_desc:
			return strcmp(a->desc, b->desc);
		case kpass_entry_data:
			if(a->data_len == 0) {
				if(b->data_len == 0) {
					// Both zero, equal
					return 0;
				} else {
					// B has data, B wins
					return 1;
				}
			} else {
				if(b->data_len == 0) {
					// A has data, A wins
					return -1;
				} else {
					// Both have data
					// Compare based on shorter length
					int r = memcmp(a->data, b->data,
						(a->data_len > b->data_len) ?
						b->data_len : a->data_len);
					// If the shorter length is equal, return diff of lengths,
					// otherwise memcmp result wins
					if(r == 0)
						return a->data_len - b->data_len;
					else
						return r;
				}
			}
		// Not really sure what to do here...
		default:
			return 0;
	}
}

kpass_entry *find_entry_ptr_uuid(kpass_db *db, uuid_t uuid) {
	uint32_t i;
	for(i = 0; i < db->entries_len; i++) {
		if(uuid_compare(uuid, db->entries[i]->uuid) == 0) {
			return db->entries[i];
		}
	}
	return NULL;
}

int find_entry_index_uuid(kpass_db *db, uuid_t uuid) {
	uint32_t i;
	for(i = 0; i < db->entries_len; i++) {
		if(uuid_compare(uuid, db->entries[i]->uuid) == 0) {
			return i;
		}
	}
	return -1;
}

int find_entry_index_ptr(kpass_db *db, kpass_entry *e) {
	uint32_t i;
	for(i = 0; i < db->entries_len; i++) {
		if(db->entries[i] == e) {
			return i;
		}
	}
	return -1;
}

int find_group_index_id(kpass_db *db, uint32_t id) {
	uint32_t i;

	for(i = 0; i < db->groups_len; i++) {
		if(db->groups[i]->id == id)
			return i;
	}
	return -1;
}

kpass_entry *remove_entry(kpass_db *db, uuid_t uuid) {
	int i = find_entry_index_uuid(db, uuid);
	kpass_entry *e;

	if(i == -1)
		return NULL;

	e = db->entries[i];

	// Shift entries left
	for(; (uint32_t)i < db->entries_len - 1; i++) {
		db->entries[i] = db->entries[i+1];
	}

	db->entries_len--;
	db->entries = realloc(db->entries, db->entries_len * sizeof(*db->entries));

	return e;
}

void insert_entry(kpass_db *db, kpass_entry *e) {
	db->entries_len++;
	db->entries = realloc(db->entries, db->entries_len * sizeof(*db->entries));
	db->entries[db->entries_len - 1] = e;

	if(find_group_index_id(db, e->group_id) == -1) {
		fix_group(db, db->entries_len - 1);
	}
}

void print_entry_diff(kpass_entry *a, kpass_entry *b) {
	kpass_entry_type i;

	for(i = 1; i < kpass_entry_num_types; i++) {
		if(compare_entry_field(i, a, b)) {
			char tmpa[60], tmpb[60];
			printf("Field %s differs.  ", entry_field_names[i]);
			// Bail out if either fails
			if(entry_field_strn(a, i, tmpa, 60) || entry_field_strn(b, i, tmpb, 60))
				continue;
			printf("\"%s\" -> \"%s\"\n", tmpa, tmpb);
		}
	}
}

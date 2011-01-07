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



/* These are helper functions that I might eventually merge into libkpass */

#include <stdio.h>
#include <uuid/uuid.h>
#include <string.h>
#include <stdlib.h>

#include "util.h"

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

void print_entry(kpass_entry *e) {
	char tmp[60];
	kpass_entry_type i;

	for(i = 1; i < kpass_entry_num_types; i++) {
		int ret = entry_field_strn(e, i, tmp, 60);
		if(ret) continue;
		printf("%s: %s\n", entry_field_names[i], tmp);
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

int find_entry_index_ptr(kpass_db *db, kpass_entry *e) {
	int i;
	for(i = 0; i < db->entries_len; i++) {
		if(db->entries[i] == e) {
			return i;
		}
	}
	return -1;
}

int find_group_index_id(kpass_db *db, int id) {
	int i;

	for(i = 0; i < db->groups_len; i++) {
		if(db->groups[i]->id == id)
			return i;
	}
	return -1;
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

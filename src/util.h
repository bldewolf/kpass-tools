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



/* These are helper functions that I might eventually merge into libkpass */

#include <kpass.h>

#include <uuid/uuid.h>

#define BRIEF_ENTRY_MASK (((1<<kpass_entry_uuid) | (1<<kpass_entry_username) | (1<<kpass_entry_title)) >> 1)
#define BRIEF_GROUP_MASK (((1<<kpass_group_id) | (1<<kpass_group_name)) >> 1)

extern char *entry_field_names[];
extern char *group_field_names[];

kpass_retval open_db(char *filename, uint8_t *pw_hash, kpass_db **db);

int compare_entry(kpass_entry *a, kpass_entry *b, int date);

int qsort_entry(const void *a, const void *b);

kpass_retval open_file(char* filename, kpass_db **db, char *pw, uint8_t pw_hash[32], int tries);

kpass_retval open_file_interactive(char* filename, kpass_db **db, uint8_t pw_hash[32], int tries);

int save_db(char* filename, kpass_db* db, uint8_t* pw_hash);

int is_metadata(kpass_entry *e);

int entry_field_strn(kpass_entry *e, kpass_entry_type t, char *str, int n);

int group_field_strn(kpass_group *e, kpass_group_type t, char *str, int n);

void print_entry(kpass_entry *e, int mask, int numeric);

void print_group(kpass_group *e, int mask, int numeric);

int compare_entry_field(kpass_entry_type t, kpass_entry *a, kpass_entry *b);

kpass_entry *find_entry_ptr_uuid(kpass_db *db, uuid_t uuid);

kpass_entry *find_entry_ptr_title(kpass_db *db, char *title);

int find_entry_index_uuid(kpass_db *db, uuid_t uuid);

int find_entry_index_ptr(kpass_db *db, kpass_entry *e);

int find_entry_index_title(kpass_db *db, char *title);

int find_group_index_id(kpass_db *db, uint32_t id);

kpass_entry *remove_entry_title(kpass_db *db, char *title);

kpass_entry *remove_entry_uuid(kpass_db *db, uuid_t uuid);

kpass_entry *remove_entry_index(kpass_db *db, int i);

void insert_entry(kpass_db *db, kpass_entry *e);

void print_entry_diff(kpass_entry *a, kpass_entry *b);

kpass_entry *init_entry();

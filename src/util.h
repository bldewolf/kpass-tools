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

#include <kpass.h>

extern char *entry_field_names[];
extern char *group_field_names[];

kpass_db* open_db(char *filename, uint8_t *pw_hash);

int compare_entry(kpass_entry *a, kpass_entry *b, int date);

int qsort_entry(const void *a, const void *b);

kpass_retval open_file(char* filename, kpass_db **db, uint8_t pw_hash[32], int tries);

int save_db(char* filename, kpass_db* db, uint8_t* pw_hash);

void fix_group(kpass_db *db, int i);

int is_metadata(kpass_entry *e);

int entry_field_strn(kpass_entry *e, kpass_entry_type t, char *str, int n);

int group_field_strn(kpass_group *e, kpass_group_type t, char *str, int n);

void print_entry(kpass_entry *e, int mask, int numeric);

void print_group(kpass_group *e, int mask, int numeric);

int compare_entry_field(kpass_entry_type t, kpass_entry *a, kpass_entry *b);

int find_entry_index_ptr(kpass_db *db, kpass_entry *e);

int find_group_index_id(kpass_db *db, int id);

void insert_entry(kpass_db *db, kpass_entry *e);

void print_entry_diff(kpass_entry *a, kpass_entry *b);


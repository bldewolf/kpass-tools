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

int is_metadata(kpass_entry *e);

void print_entry(kpass_entry *e);

int compare_entry_field(kpass_entry_type t, kpass_entry *a, kpass_entry *b);

int find_entry_index_ptr(kpass_db *db, kpass_entry *e);

int find_group_index_id(kpass_db *db, int id);

void insert_entry(kpass_db *db, kpass_entry *e);

extern char *entry_field_names[];

void print_entry_diff(kpass_entry *a, kpass_entry *b);

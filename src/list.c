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

#include <kpass.h>

#include "util.h"

int list_main(int argc, char* argv[]) {
	kpass_db *db;
	uint8_t pw_hash[32];
	char* dest;
	int i;
	int mod = 0;

	if(argc != 2) return 1;

	if(open_file(argv[1], &db, pw_hash, 3)) {
		puts("Open file failed");
	}

	if(!db)
		return 1;

	for(i = 0; i < db->entries_len; i++) {
		if(is_metadata(db->entries[i]))
			continue;

		print_entry(db->entries[i]);
	}

	return 0;
}

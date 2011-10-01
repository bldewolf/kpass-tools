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

#include "lib/yesno.h"

#include "util.h"

int merge_main(int argc, char* argv[]) {
	kpass_db *dbs[2];
	uint8_t pw_hash[2][32];
	char* dest;
	int i;
	int mod = 0;

	int target, source;

	if(argc != 3) return 1;

	if(open_file(argv[1], &dbs[0], NULL, pw_hash[0], 3) ||
		open_file(argv[2], &dbs[1], NULL, pw_hash[1], 3)) {
		puts("Open file failed somehow");
	}

	if(!dbs[0] && !dbs[1])
		return 1;

	source = 0;
	target = 1;

	puts("qsorting");

	qsort(dbs[source]->entries, dbs[source]->entries_len,
		sizeof(*dbs[source]->entries), qsort_entry);
		
	puts("Searching for dups");

	for(i = 0; i < dbs[target]->entries_len; i++) {
		kpass_entry **br, *source_e, *target_e, *tmp;
		char c;
		int source_i;

		if(is_metadata(dbs[target]->entries[i]))
			continue;

		target_e = dbs[target]->entries[i];

//		puts("Searching for entry:");
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
			puts("The following differences were found:");
			print_entry_diff(target_e, source_e);

			printf("Replace entry? (yes/no) ");
			if(yesno()) {
				mod = 1;
				puts("Swapping entries...");
				source_i = find_entry_index_ptr(dbs[source], source_e);
				tmp = dbs[source]->entries[source_i];
				dbs[source]->entries[source_i] = target_e;
				dbs[target]->entries[i] = tmp;

				if(find_group_index_id(dbs[target], tmp->group_id) == -1) {
					puts("Entry group ID not found, setting to first listed group.");
					fix_group(dbs[target], i);
				}
			} else {
				puts("Skipping...");
			}
		}
	}

	puts("Okay finished");
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
		puts("No changes found, not bothering saving.");
	}

	return 0;
}

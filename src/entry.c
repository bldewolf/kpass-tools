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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <kpass.h>

#include "lib/getpass.h"

#include "util.h"

static void print_help() {
	puts("kpass-tools entry - add/delete/modify entries in a database\n\
Usage: kpass-tools entry <options>\n\
Available Options:\n\
\n\
General options:\n\
    -s        source database\n\
    -o        output database\n\
    -p        source database password\n\
    -f        disable safety checks (duplicate UUIDs, non-existent groups, etc)\n\
    -h        this displays the help\n\
\n\
Set mode:\n\
    -a        add new entry with given fields\n\
    -d        delete entries matching criteria\n\
    -m        modify entries matching criteria\n\
\n\
Set entry fields for add/modify:\n\
    -t <str>  entry title\n\
    -r <str>  entry URL\n\
    -n <str>  entry notes\n\
    -u <uuid> entry UUID (default: random)\n\
    -g <int>  entry group ID (default: first group)\n\
    -i <int>  entry icon ID\n\
    -w <str>  entry password\n\
    -W        entry password via stdin\n\
    -k        entry password via prompt\n\
\n\
Matching entry fields for modify/delete:\n\
    -T <str>  entry title\n\
    -U <uuid> entry UUID");
}

enum modes {
	ADD = 1,
	MODIFY,
	DELETE
};

#define BIT(x) (1 << (x))

int entry_main(int argc, char* argv[]) {
	kpass_db *db = NULL;
	uint8_t pw_hash[32];
	char* pw = NULL;
	char c;
	kpass_entry *new_entry = calloc(1, sizeof(kpass_entry));
	kpass_entry search_entry = {{0}};
	int new_fields = 0, search_fields = 0;
	char *src = NULL, *out = NULL;
	int force = 0;
	enum modes mode = 0;
	char * pw_file = NULL;
	int pw_prompt = 0;

	/* XXX: Most of the fields can be overwritten except for the password.
	 * Should we be consistent or lazy? */
	while((c = getopt(argc, argv, "s:o:p:fadmt:r:n:u:g:i:w:WkT:U:h")) != -1) {
		switch(c) {
			case 's':
				src = optarg;
				break;
			case 'o':
				out = optarg;
				break;
			case 'p':
				pw = optarg;
				break;
			case 'f':
				force = 1;
				break;
			case 'a':
				if(mode) {
					fprintf(stderr, "Cannot set multiple modes.\n");
					goto entry_main_cleanup;
				}
				mode = ADD;
				break;
			case 'd':
				if(mode) {
					fprintf(stderr, "Cannot set multiple modes.\n");
					goto entry_main_cleanup;
				}
				mode = DELETE;
				break;
			case 'm':
				if(mode) {
					fprintf(stderr, "Cannot set multiple modes.\n");
					goto entry_main_cleanup;
				}
				mode = MODIFY;
				break;
			case 't':
				if(new_entry->title) free(new_entry->title);
				new_entry->title = strdup(optarg);
				new_fields |= BIT(kpass_entry_title);
				break;
			case 'r':
				if(new_entry->url) free(new_entry->url);
				new_entry->url = strdup(optarg);
				new_fields |= BIT(kpass_entry_url);
				break;
			case 'n':
				if(new_entry->notes) free(new_entry->notes);
				new_entry->notes = strdup(optarg);
				new_fields |= BIT(kpass_entry_notes);
				break;
			case 'u':
				if(uuid_parse(optarg, new_entry->uuid)) {
					fprintf(stderr, "Failed to parse new UUID.\n");
					goto entry_main_cleanup;
				}
				new_fields |= BIT(kpass_entry_uuid);
				break;
			case 'g':
				new_entry->group_id = atoi(optarg);
				new_fields |= BIT(kpass_entry_group_id);
				break;
			case 'i':
				new_entry->image_id = atoi(optarg);
				new_fields |= BIT(kpass_entry_image_id);
				break;
			case 'w':
				if(new_fields & BIT(kpass_entry_password)) {
					fprintf(stderr, "Only one password source may be specified.\n");
					goto entry_main_cleanup;
				}
				new_entry->password = strdup(optarg);
				new_fields |= BIT(kpass_entry_password);
				break;
			case 'W':
				if(new_fields & BIT(kpass_entry_password)) {
					fprintf(stderr, "Only one password source may be specified.\n");
					goto entry_main_cleanup;
				}
				pw_file = optarg;
				new_fields |= BIT(kpass_entry_password);
				break;
			case 'k':
				if(new_fields & BIT(kpass_entry_password)) {
					fprintf(stderr, "Only one password source may be specified.\n");
					goto entry_main_cleanup;
				}
				pw_prompt = 1;
				new_fields |= BIT(kpass_entry_password);
				break;
			case 'T': /* TODO: Support combined search? */
				if(search_fields) {
					fprintf(stderr, "Only one search parameter may be specified.\n");
					goto entry_main_cleanup;
				}
				search_entry.title = optarg;
				search_fields |= BIT(kpass_entry_title);
				break;
			case 'U':
				if(search_fields) {
					fprintf(stderr, "Only one search parameter may be specified.\n");
					goto entry_main_cleanup;
				}
				if(uuid_parse(optarg, search_entry.uuid)) {
					fprintf(stderr, "Failed to parse search UUID.\n");
					goto entry_main_cleanup;
				}
				search_fields |= BIT(kpass_entry_uuid);
				break;
			case 'h':
				print_help();
				goto entry_main_cleanup;
			case '?':
				goto entry_main_cleanup;
			default:
				fprintf(stderr, "HOW DID I GET HERE\n");
				goto entry_main_cleanup;

		}
	}

	/* check args */
	if(!src) {
		fprintf(stderr, "No source file specified.\n");
		goto entry_main_cleanup;
	}
	if(!out) {
		fprintf(stderr, "No output file specified.\n");
		goto entry_main_cleanup;
	}
	if(!mode) {
		fprintf(stderr, "No mode specified.\n");
		goto entry_main_cleanup;
	}
	if(mode == MODIFY && !new_fields) {
		fprintf(stderr, "Must specify fields to set in modify mode.\n");
		goto entry_main_cleanup;
	}
	if(mode == DELETE && new_fields) {
		fprintf(stderr, "Only search fields allowed in delete mode.\n");
		goto entry_main_cleanup;
	}
	if((mode == MODIFY || mode == DELETE) && !search_fields) {
		fprintf(stderr, "No search fields specified.\n");
		goto entry_main_cleanup;
	}

	/* Read the new password from a file or stdin */
	if(pw_file) {
		FILE *fs;
		char *end;
		if(!strcmp(pw_file, "-")) {
			fs = fdopen(STDIN_FILENO, "r");
		} else {
			fs = fopen(pw_file, "r");
		}
		if(!fs) {
			fprintf(stderr, "Failed to open password file %s: %m.\n", pw_file);
			goto entry_main_cleanup;
		}

		/* XXX: This needs a loop to handle longer passwords */
		new_entry->password = malloc(1024);
		if(!fgets(new_entry->password, 1024, fs)) {
			fprintf(stderr, "Failed to read password file %s: %m.\n", pw_file);
			goto entry_main_cleanup;
		}
		end = strchr(new_entry->password, '\n');
		if(!end && !feof(fs)) {
			fprintf(stderr, "Failed to read entire password (1024 byte limit)\n");
			goto entry_main_cleanup;
		}
		/* Terminate the string on the newline, if there is one */
		if(end) {
			end[0] = 0;
		}

		if(fclose(fs)) {
			fprintf(stderr, "Failed to close password file %s: %m.\n", pw_file);
			goto entry_main_cleanup;
		}
	}
	/* collect the new password interactively if it wasn't already */
	if(pw_prompt || !new_entry->password) {
		new_entry->password = strdup(getpass("New password:"));
		char * confirm = getpass("Confirm:");

		if(strcmp(new_entry->password, confirm)) {
			fprintf(stderr, "Passwords don't match.\n");
			goto entry_main_cleanup;
		}
	}

	if(open_file(src, &db, pw, pw_hash, 3)) {
		fprintf(stderr, "Open file %s failed\n", src);
		goto entry_main_cleanup;
	}

	/* Set defaults that aren't empty/null/zero */
	if(mode == ADD) {
		if(!(new_fields & BIT(kpass_entry_uuid))) {
			uuid_generate(new_entry->uuid);
		}
		if(!(new_fields & BIT(kpass_entry_group_id))) {
			new_entry->group_id = db->groups[0]->id;
		}
	}

	if(mode == ADD) {
		if(!force) {
			if(-1 == find_entry_index_uuid(db, new_entry->uuid)) {
				fprintf(stderr, "UUID already exists in database.\n");
				goto entry_main_cleanup;
			}
			if(-1 == find_group_index_id(db, new_entry->group_id)) {
				fprintf(stderr, "Group ID (%d) not in database.\n",
					new_entry->group_id);
				goto entry_main_cleanup;
			}
		}
		insert_entry(db, new_entry);
	} else if(mode == MODIFY) { /* TODO: Modify more than the first one? */
		if(!force) {
			if((new_fields & BIT(kpass_entry_uuid)) &&
				-1 == find_entry_index_uuid(db, new_entry->uuid)) {
				fprintf(stderr, "UUID already exists in database.\n");
				goto entry_main_cleanup;
			}
			if((new_fields & BIT(kpass_entry_group_id)) &&
				-1 == find_group_index_id(db, new_entry->group_id)) {
				fprintf(stderr, "Group ID (%d) not in database.\n",
					new_entry->group_id);
				goto entry_main_cleanup;
			}
		}

		kpass_entry *e = NULL;
		if(search_fields == BIT(kpass_entry_title)) {
			e = find_entry_ptr_title(db, search_entry.title);
		} else if(search_fields == BIT(kpass_entry_uuid)) {
			e = find_entry_ptr_uuid(db, search_entry.uuid);
		} else {
			fprintf(stderr, "No search fields specified.\n");
			goto entry_main_cleanup;
		}
		if(!e) {
			fprintf(stderr, "No entries found matching that criteria.\n");
			goto entry_main_cleanup;
		}

		if(new_fields & BIT(kpass_entry_title)) {
			free(e->title);
			e->title = new_entry->title;
			new_entry->title = NULL;
		}
		if(new_fields & BIT(kpass_entry_url)) {
			free(e->url);
			e->url = new_entry->url;
			new_entry->url = NULL;
		}
		if(new_fields & BIT(kpass_entry_notes)) {
			free(e->notes);
			e->notes = new_entry->notes;
			new_entry->notes = NULL;
		}
		if(new_fields & BIT(kpass_entry_uuid)) {
			uuid_copy(e->uuid, new_entry->uuid);
		}
		if(new_fields & BIT(kpass_entry_group_id)) {
			e->group_id = new_entry->group_id;
		}
		if(new_fields & BIT(kpass_entry_image_id)) {
			e->image_id = new_entry->image_id;
		}
		if(new_fields & BIT(kpass_entry_password)) {
			free(e->password);
			e->password = new_entry->password;
			new_entry->password = NULL;
		}
	} else if(mode == DELETE) {
		kpass_entry *e = NULL;
		if(search_fields == BIT(kpass_entry_title)) {
			e = remove_entry_title(db, search_entry.title);
		} else if(search_fields == BIT(kpass_entry_uuid)) {
			e = remove_entry_uuid(db, search_entry.uuid);
		} else {
			fprintf(stderr, "No search fields specified.\n");
			goto entry_main_cleanup;
		}
		if(!e) {
			fprintf(stderr, "No entries found matching that criteria.\n");
			goto entry_main_cleanup;
		}
	} else {
		fprintf(stderr, "No mode specified.\n");
		goto entry_main_cleanup;
	}

	save_db(out, db, pw_hash);

	kpass_free_db(db);
	kpass_free_entry(new_entry);
	return 0;

entry_main_cleanup:
	if(db)
		kpass_free_db(db);
	kpass_free_entry(new_entry);
	return 1;
}

/*
* Copyright 1999-2006 University of Chicago
* 
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
* 
* http://www.apache.org/licenses/LICENSE-2.0
* 
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*/

/* FTP extensions in support of RFC3659 */

/**********************************************************************
*
* This code stolen from the GLOBUS Alliance, which did the work
* of extending wu-ftpd (up until release 3.2.1 of their suite) to
* include RFC 2569 commands MLSD and MLST.
*
* This file strictly deals with the MLST and MLSD commands.
*
*********************************************************************/

#include "config.h"
#include "proto.h"
#include "extensions.h"
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
#include <unistd.h>
#include <time.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
 
char *mapping_getcwd(char *path, size_t size);
const char *get_mlsx_options(void);

static char * options = NULL;
     
void mlsx_options(const char *new_options) {
    if(options)
	free(options);
  
    if(new_options) {
        options = strdup(new_options);
    } else {
	options = NULL;
    }
}

const char *get_mlsx_options(void) {
    if(!options)
	return "Type;Size;Modify;Perm;Charset;UNIX.mode;UNIX.slink;Unique;";

    return options;
}

void get_abs_path(const char *path, char *abs_path, int size) {
    char *slash;
     
    if(!path) {
	mapping_getcwd(abs_path, size);
    } else if(*path == '/') {
	strncpy(abs_path, path, size);
    } else {
	char cwd[MAXPATHLEN];
 
	snprintf(abs_path, size, "%s/%s", mapping_getcwd(cwd, sizeof(cwd)),
		path);
    }

    abs_path[size - 1] = 0;

    slash = strrchr(abs_path, '/');
    if(slash && slash != abs_path && *(slash + 1) == '\0')
	*slash = '\0';
}

/*********************************************************************
*
* mlst(), called from ftpcmd.y
*
* MLST takes a path, be it absolute or NULL, and returns the 'facts'
* about the file or directory in question.
*
*********************************************************************/
void mlst(const char *path) {
    char full_path[MAXPATHLEN];
    char fact_str[2048];
    
    get_abs_path(path, full_path, sizeof(full_path));
        
    if(get_fact_string(fact_str, sizeof(fact_str),
				full_path, get_mlsx_options())) {
	reply(501, "No such file or insufficient permissions");
    } else {
	lreply(250, "Listing %s", path);
	lreply(0, " %s", fact_str);
	reply(250, "End");
    }
}

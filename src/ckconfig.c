/****************************************************************************  
 
  Copyright (c) 1999-2003 WU-FTPD Development Group.  
  All rights reserved.
  
  Portions Copyright (c) 1980, 1985, 1988, 1989, 1990, 1991, 1993, 1994
    The Regents of the University of California.
  Portions Copyright (c) 1993, 1994 Washington University in Saint Louis.
  Portions Copyright (c) 1996, 1998 Berkeley Software Design, Inc.
  Portions Copyright (c) 1989 Massachusetts Institute of Technology.
  Portions Copyright (c) 1998 Sendmail, Inc.
  Portions Copyright (c) 1983, 1995, 1996, 1997 Eric P.  Allman.
  Portions Copyright (c) 1997 by Stan Barber.
  Portions Copyright (c) 1997 by Kent Landfield.
  Portions Copyright (c) 1991, 1992, 1993, 1994, 1995, 1996, 1997
    Free Software Foundation, Inc.  
 
  Use and distribution of this software and its source code are governed 
  by the terms and conditions of the WU-FTPD Software License ("LICENSE").
 
  If you did not receive a copy of the license, it may be obtained online
  at http://www.wu-ftpd.info/license.html.
 
  $Id: ckconfig.c,v 1.9 2011/10/20 22:58:10 wmaton Exp $
 
****************************************************************************/
#include "config.h"
#include "proto.h"
#if !defined(HOST_ACCESS)
#  define HOST_ACCESS  1
#endif /* !defined(HOST_ACCESS) */ 
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/stat.h>
#include "pathnames.h"
#if defined(VIRTUAL) && defined(INET6)
#  include <netinet/in.h>
#endif /* defined(VIRTUAL) && defined(INET6) */ 

/* Prototypes */
void print_copyright(void);

/*
** Check the modes below and customize for your local 
** security/administrative policy.  Please be aware that
** what you see below is the recommended modes for the
** various WU-FTPD configuration and log files.
*/

#define FTPSERVERS_MODES       0644 
#define FTPPID_MODES           0644 
#define FTPACCESS_MODES        0644 
#define FTPCONVERSIONS_MODES   0644 
#define FTPGROUPS_MODES        0644 
#define FTPHOSTS_MODES         0644 
#define FTPUSERS_MODES         0644 
#define XFERLOG_MODES          0640 

/*
** Used in file modes checking
*/
#define PASSED           0
#define MISSING         -1
#define BADFILETYPE     -2
#define BADPERMS        -3

/*************************************************************************/
/* FUNCTION  : checkdest                                                 */
/* PURPOSE   : Check the modes on the path passed in                     */
/* ARGUMENTS : path to be  examined                                      */
/* ARGUMENTS : message number to be displayed if stat fails              */
/* ARGUMENTS : recommended modes                                         */
/* RETURNS   : MISSING     - file is not there to stat                   */
/*           : BADFILETYPE - if not regular file                         */
/*           : BADPERMS    - if permissions don't match                  */
/*           : PASSED      - if permissions do match                     */
/*************************************************************************/

static int checkdest(char *path, int msgnum, mode_t modes)
{
    struct stat sbuf;

    if ((stat(path, &sbuf)) < 0) {
       switch (msgnum) {
         case 1: printf("I can't find it... look in doc/examples for an example.\n");;
                 break;
	 case 2: printf("I can't find it... \n");
                 break;
	 case 3: printf("Doesn't exist in virtual config dir...  Using system-wide version.\n");
                 break;
       }
       return(MISSING);
    }

    /*
    ** Checks the modes required versus what is on the file.
    */
    if ((sbuf.st_mode & S_IFMT) != S_IFREG) {
        printf("%s: not a regular file!.\n",path);
        return(BADFILETYPE);
    }

    if ((sbuf.st_mode & 0777) != modes) {
        printf("%s - Incorrect file modes. Should be %.4o\n", path, modes); 
        return(BADPERMS);
    }

    printf("ok.\n");
    return(PASSED);
}

int main(int argc, char **argv)
{
    struct stat sbuf;
    char *sp;
    char buf[1024];
    int c;

#if defined(VIRTUAL)
    int warning = 0;
    FILE *svrfp;
    char accesspath[MAXPATHLEN];
#  if defined(INET6)
    char hostaddress[INET6_ADDRSTRLEN];
#  else /* !(defined(INET6)) */ 
    char hostaddress[32];
#  endif /* !(defined(INET6)) */ 
#endif /* defined(VIRTUAL) */ 

    if (argc > 1) {
	while ((c = getopt(argc, argv, "V")) != EOF) {
	    switch (c) {
	    case 'V':
		print_copyright();
		exit(0);
	    default:
		fprintf(stderr, "usage: %s [-V]\n", argv[0]);
		exit(1);
	    }
	}
    }

    printf("------------------------------------------------\n");
    printf("Checking SYSTEM-WIDE WU-FTPD Configuration Files\n");
    printf("------------------------------------------------\n");

    /* _PATH_FTPUSERS  */
    printf("\nChecking _PATH_FTPUSERS :: %s\n", _PATH_FTPUSERS);
    checkdest(_PATH_FTPUSERS, 1, FTPUSERS_MODES);

    /* _PATH_FTPACCESS  */
    printf("\nChecking _PATH_FTPACCESS :: %s\n", _PATH_FTPACCESS);
    checkdest(_PATH_FTPACCESS, 1, FTPACCESS_MODES);

    /* _PATH_PIDNAMES   */
    printf("\nChecking _PATH_PIDNAMES :: %s\n", _PATH_PIDNAMES);
    strlcpy(buf, _PATH_PIDNAMES, sizeof(buf));
    sp = (char *) strrchr(buf, '/');
    *sp = '\0';
    if ((stat(buf, &sbuf)) < 0) {
        printf("I can't find it...\n");
        printf("You need to make this directory [%s] in order for\n", buf);
        printf("the limit and user count functions to work.\n");
    }
    else
        printf("ok.\n");

    /* _PATH_CVT        */
    printf("\nChecking _PATH_CVT :: %s\n", _PATH_CVT);
    checkdest(_PATH_CVT, 1, FTPCONVERSIONS_MODES);

    /* _PATH_XFERLOG    */
    printf("\nChecking _PATH_XFERLOG :: %s\n", _PATH_XFERLOG);
    if (checkdest(_PATH_XFERLOG, 2, XFERLOG_MODES) == MISSING) {
	printf("Don't worry, it will be created automatically by the\n");
	printf("server if you do transfer logging.\n");
    }

    /* _PATH_PRIVATE    */
    printf("\nChecking _PATH_PRIVATE :: %s\n", _PATH_PRIVATE);
    if (checkdest(_PATH_PRIVATE, 1, FTPGROUPS_MODES) == MISSING) {
       printf("You only need this if you want SITE GROUP and SITE GPASS\n");
       printf("functionality. If you do, you will need to edit the example.\n");
    }


    /* _PATH_FTPHOSTS   */
    printf("\nChecking _PATH_FTPHOSTS :: %s\n", _PATH_FTPHOSTS);
    if (checkdest(_PATH_FTPHOSTS, 1, FTPHOSTS_MODES) == MISSING) {
	printf("You only need this if you are using the HOST ACCESS\n");
	printf("features of the server.\n");
    }

#if defined(VIRTUAL)

    /* _PATH_FTPSERVERS  */
    printf("\nChecking _PATH_FTPSERVERS :: %s\n", _PATH_FTPSERVERS);
    if (checkdest(_PATH_FTPSERVERS, 1, FTPSERVERS_MODES) != MISSING) {

	/* Need to check the access files specified in the ftpservers file. */
	if ((svrfp = fopen(_PATH_FTPSERVERS, "r")) == NULL)
	    printf("I can't open it! check permissions and run ckconfig again.\n");
	else {
	    while (read_servers_line(svrfp, hostaddress, sizeof(hostaddress), accesspath, sizeof(accesspath)) == 1) {
		printf("\n------------------------------------------------\n");
		printf("Checking VIRTUAL HOST %s\n\nConfiguration files in %s", hostaddress, accesspath);
		printf("\n------------------------------------------------\n");
		/*
		** check to see that a valid directory value was
		** supplied and not something such as "INTERNAL"
		**
		** It is valid to have a string such as "INTERNAL" in the
		** ftpservers entry. This is not an error. Silently ignore it.
		*/
		if (stat(accesspath, &sbuf) == 0) {
		    if ((sbuf.st_mode & S_IFMT) != S_IFDIR) {
			printf("Check servers file and make sure only directories are listed...\n");
			printf("Look in doc/examples for an example.\n");
                    }
		    else {
                        /*
                        ** The directory exists so check the support files in 
                        ** the virtual host config directory 
                        */

                	/* FTPACCESS  */
                	snprintf(buf, sizeof(buf),"%s/ftpaccess", accesspath);
                	printf("\nChecking %s\n", buf);
                	if (checkdest(buf, 3, FTPACCESS_MODES) == MISSING)
                            warning++;
	
                	/* FTPCONVERSIONS  */
                	snprintf(buf, sizeof(buf),"%s/ftpconversions", accesspath);
                	printf("\nChecking %s\n", buf);
                	if (checkdest(buf, 3, FTPCONVERSIONS_MODES) == MISSING)
                            warning++;

                	/* FTPGROUPS  */
                	snprintf(buf, sizeof(buf),"%s/ftpgroups", accesspath);
                	printf("\nChecking %s\n", buf);
                	if (checkdest(buf, 3, FTPGROUPS_MODES) == MISSING)
                            warning++;
	
                	/* FTPHOSTS  */
                	snprintf(buf, sizeof(buf),"%s/ftphosts", accesspath);
                	printf("\nChecking %s\n", buf);
                	if (checkdest(buf, 3, FTPHOSTS_MODES) == MISSING)
                            warning++;

                	/* FTPUSERS  */
                	snprintf(buf, sizeof(buf),"%s/ftpusers", accesspath);
                	printf("\nChecking %s\n", buf);
                	if (checkdest(buf, 3, FTPUSERS_MODES) == MISSING)
                            warning++;
		    }
		}
		else if (strcasecmp(accesspath,"INTERNAL") == 0) {
	            printf("INTERNAL usage indicated.\n");
	            printf("Using system-wide configuration files for %s.\n", 
                           hostaddress);
                }
		else {
	            printf("Configuration directory %s does not exist.\n", accesspath);
	            printf("Create the directory and supporting config files and run ckconfig again.\n");
		    printf("Internal ftpaccess usage currently in effect... ok.\n");
                }
	    }
	    fclose(svrfp);
	}
    }

    if (warning > 0) {
	printf("\nNote: Configuration files in virtual config directories override\n");
	printf("    : system-wide configuration defaults.  If there is no reason\n");
	printf("    : to override a system-wide configuration file, you do not\n");
	printf("    : need to place one in the virtual directory.\n");
    }
#endif /* defined(VIRTUAL) */ 

    return (0);
}

/**************************************************************************** 

   Copyright (c) 1999-2003 WU-FTPD Development Group. 
   All rights reserved.
   
   Portions Copyright (c) 1980, 1985, 1988, 1989, 1990, 1991, 1993, 1994 
   The Regents of the University of California.  Portions Copyright (c) 
   1993, 1994 Washington University in Saint Louis.  Portions Copyright 
   (c) 1996, 1998 Berkeley Software Design, Inc.  Portions Copyright (c) 
   1998 Sendmail, Inc.  Portions Copyright (c) 1983, 1995, 1996, 1997 Eric 
   P. Allman.  Portions Copyright (c) 1989 Massachusetts Institute of 
   Technology.  Portions Copyright (c) 1997 by Stan Barber.  Portions 
   Copyright (C) 1991, 1992, 1993, 1994, 1995, 1996, 1997 Free Software 
   Foundation, Inc.  Portions Copyright (c) 1997 by Kent Landfield. 
 
   Use and distribution of this software and its source code are governed 
   by the terms and conditions of the WU-FTPD Software License ("LICENSE"). 
 
   $Id: privatepw.c,v 1.8 2009/04/19 10:35:43 wmaton Exp $
 
****************************************************************************/
/*
   Subsystem:  WU-FTPD FTP Server
   Purpose:    Change WU-FTPD Guest Passwords
   File Name:  privatepw.c               

   usage: privatepw [-c] [-f passwordfile] [-g group] accessgroup
   privatepw [-d] [-f passwordfile] accessgroup
   privatepw [-l] [-f passwordfile] 
   -c:           creates a new file.
   -d:           deletes specified accessgroup.
   -l:           list contents of ftpgroups file.
   -f ftpgroups: updates the specified file.
   -g group:     set real group to the specified group.

   This software was initially written by Kent Landfield (kent@landfield.com)
 */

#include "../../src/config.h"
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/signal.h>
#include <sys/stat.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <grp.h>
#include <unistd.h>
#include "../../src/pathnames.h"

#define BUFLEN 256
#define GROUPLEN 8

static char *tmp;
static char line[BUFLEN];
static FILE *fp;
static int verbose = 0;
static char *passwdpath;

static unsigned char itoa64[] =	/* 0 ... 63 => ascii - 64 */
"./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

void print_copyright(void);

static void usage(void)
{
    fprintf(stderr, "usage: privatepw [-c] [-f ftpgroups] [-g group] accessgroup\n");
    fprintf(stderr, "       privatepw [-d] [-f ftpgroups] accessgroup\n");
    fprintf(stderr, "       privatepw [-l] [-f ftpgroups]\n");
    fprintf(stderr, "\t\t-c:           creates a new file.\n");
    fprintf(stderr, "\t\t-d:           deletes specified accessgroup.\n");
    fprintf(stderr, "\t\t-l:           list contents of ftpgroups file.\n");
    fprintf(stderr, "\t\t-f ftpgroups: updates the specified file.\n");
    fprintf(stderr, "\t\t-g group:     set real group to the specified group.\n");
    exit(EXIT_SUCCESS);
}

static void to64(register char *s, register long v, register int n)
{
    while (--n >= 0) {
	*s++ = itoa64[v & 0x3f];
	v >>= 6;
    }
}

static void terminate(void)
{
    if (tmp)
	(void) unlink(tmp);
    exit(EXIT_FAILURE);
}

static void catchintr(void)
{
    fprintf(stderr, "Interrupted.\n");
    terminate();
}

static char *savit(char *s)
{
    char *d;
    int len;

    if (s == NULL)
	terminate();

    len = strlen(s)+1;

    if ((d = (char *) malloc(len)) == NULL) {
	fprintf(stderr, "Whoa... Malloc failed.\n");
	terminate();
    }
    strlcpy(d, s, len);
    return (d);
}

static int confirmed(char *accessgroup)
{
    register int ch;

    printf("Delete %s: Are your sure ? (y/n) ", accessgroup);
    ch = getc(stdin);
    if (ch == 'y')
	return (1);
    return (0);
}

static char *getgroup(char *msg)
{
    register int ch;
    register char *p;
    static char buf[GROUPLEN + 1];

    (void) fputs(msg, stderr);
    rewind(stderr);		/* implied flush */
    for (p = buf; (ch = getc(stdin)) != EOF && ch != '\n';)
	if (p < buf + GROUPLEN)
	    *p++ = ch;

    if (p > buf+GROUPLEN) {
	fprintf(stderr, "group name too long...\n");
	terminate();
    }
    else
        *p = '\0';

    if (getgrnam(buf) == NULL) {
	fprintf(stderr, "Invalid group \'%s\' specified\n", buf);
	terminate();
    }
    return (buf);
}

#if !defined(NO_CRYPT_PROTO)
extern char *crypt(const char *, const char *);
#endif /* !defined(NO_CRYPT_PROTO) */ 
extern char *getpass(const char *prompt);

static void addrecord(char *accessgroup, char *sysgroup, size_t slen, char *msg, FILE *f)
{
    char *pw, *cpw, salt[3];

    printf("%s %s\n", msg, accessgroup);

    if (sysgroup[0] == '\0')
	strlcpy(sysgroup, getgroup("Real System Group to use: "), slen);

    pw = savit((char *) getpass("New password: "));
    if (strcmp(pw, (char *) getpass("Re-type new password: "))) {
	fprintf(stderr, "They don't match, sorry.\n");
	if (tmp)
	    unlink(tmp);
        free(pw);
	exit(EXIT_FAILURE);
    }

    srand((int) time((time_t *) NULL));
    to64(&salt[0], rand(), 2);
    cpw = crypt(pw, salt);
    free(pw);
    fprintf(f, "%s:%s:%s\n", accessgroup, cpw, sysgroup);
}

static void list_privatefile(char *privatefile)
{
    if (verbose)
	fprintf(stderr, "Private File: %s file.\n", privatefile);

    if ((fp = fopen(privatefile, "r")) == NULL) {
	fprintf(stderr, "Could not open %s file.\n", privatefile);
	exit(EXIT_FAILURE);
    }

    printf("\nWU-FTPD Private file: %s\n", privatefile);
    printf("accessgroup : password : system group\n");
    printf("-------\n");

    while (fgets(line, BUFLEN, fp) != NULL)
	fputs(line, stdout);
    printf("-------\n");
}

int main(int argc, char **argv)
{
    extern void (*signal(int sig, void (*disp) (int))) (int);
    extern int getopt(int argc, char *const *argv, const char *optstring);
    extern char *optarg;
    extern int optind;
    extern int opterr;

    struct stat stbuf;

    char realgroup[BUFLEN];
    char *cp;

    char accessgroup[BUFLEN];
    char w[BUFLEN];
    char *command[4];

    int create;
    int delete;
    int list;
    int found;
    int lineno;
    int c;

    FILE *tfp;
    int tfd;
    char tmpname[BUFLEN];

    pid_t cp_pid;

    opterr = 0;
    create = 0;
    delete = 0;
    list = 0;

    tmp = NULL;
    realgroup[0] = '\0';

    passwdpath = NULL;

    if (argc == 1)
	usage();

    while ((c = getopt(argc, argv, "Vvcdf:g:l")) != EOF) {
	switch (c) {
	case 'd':
	    delete++;
	    break;
	case 'c':
	    create++;
	    break;
	case 'f':
	    passwdpath = strdup(optarg);
	    break;
	case 'g':
	    /* Let's make sure our group name isn't longer than BUFLEN */
	    if (strlen(optarg) > BUFLEN) {
		fprintf(stderr, "Group name too long.\n");
		return(1);
	    } else
		strlcpy(realgroup, optarg, sizeof(realgroup));
	    if (getgrnam(realgroup) == NULL) {
		fprintf(stderr, "Invalid group \'%s\' specified\n", realgroup);
		return (1);
	    }
	    break;
	case 'l':
	    list++;
	    break;
	case 'v':
	    verbose++;
	    break;
	case 'V':
	    print_copyright();
	    return (0);
	    /* NOTREACHED */
	default:
	    usage();
	}
    }

    if (passwdpath == NULL)  /* set the default path */
       passwdpath = strdup(_PATH_PRIVATE);

    if (list) {
	list_privatefile(passwdpath);
	return (0);
    }

    if (optind >= argc) {
	fprintf(stderr, "Need to specify an accessgroup name.\n");
	usage();
    }

    signal(SIGINT, (void (*)()) catchintr);

    /* Let's check to make sure argv[optind] isn't larger than BUFLEN
     * and if it is there is no point in continuing since simply
     * truncating the group name is useless, because it results in
     * a group name other than that intended by the user
     */
    if(strlen(argv[optind]) > BUFLEN) {
	fprintf(stderr, "Specified accessgroup name is too large.\n");
	return(1);
    } else
	strlcpy(accessgroup, argv[optind], sizeof(accessgroup));

    if (create) {
	if (stat(passwdpath, &stbuf) == 0) {
	    fprintf(stderr, "%s exists, cannot create it.\n", passwdpath);
	    fprintf(stderr, "Remove -c option or use the -f option to specify another.\n");
	    return (1);
	}

	if ((tfp = fopen(passwdpath, "w")) == NULL) {
	    fprintf(stderr, "Could not open \"%s\" for writing.\n", passwdpath);
	    perror("fopen");
	    return (1);
	}

	tmp = passwdpath;

	printf("Creating WU-FTPD Private file: %s\n", passwdpath);
	addrecord(accessgroup, realgroup, sizeof(realgroup), "Adding accessgroup", tfp);

	fclose(tfp);
	return (0);
    }

#if defined(HAVE_MKSTEMP)
    strlcpy(tmpname, "/tmp/privatepwXXXXXX", sizeof(tmpname));
    tmp = tmpname;
    tfd = mkstemp(tmp);
    if(tfd < 0) {
	fprintf(stderr, "Could not open temp file.\n");
	return(1);
    }
#else /* !(defined(HAVE_MKSTEMP)) */ 
#  if defined(HAVE_MKTEMP)
    tmp = mktemp("/tmp/privatepwXXXXXX");
#  else /* !(defined(HAVE_MKTEMP)) */ 
    tmp = tmpnam(NULL);
#  endif /* !(defined(HAVE_MKTEMP)) */ 
#endif /* !(defined(HAVE_MKSTEMP)) */ 

#if defined(HAVE_MKSTEMP)
    if ((tfp = fdopen(tfd, "w")) == NULL) {
        unlink(tmp);
#else /* !(defined(HAVE_MKSTEMP)) */ 
    if ((tfp = fopen(tmp, "w")) == NULL) {
#endif /* !(defined(HAVE_MKSTEMP)) */ 
	fprintf(stderr, "Could not open temp file.\n");
	return (1);
    }

    if ((fp = fopen(passwdpath, "r")) == NULL) {
	fprintf(stderr, "Could not open %s file.\n", passwdpath);
	fprintf(stderr, "Use -c option to create new one.\n");
	return (1);
    }

    lineno = 0;
    found = 0;

    while (fgets(line, BUFLEN, fp) != NULL) {
	lineno++;

	if (found || (line[0] == '#') || (!line[0])) {
	    fputs(line, tfp);
	    continue;
	}

	strlcpy(w, line, sizeof(w));

	if ((cp = strchr(w, ':')) == NULL) {
	    fprintf(stderr, "%s: line %d: invalid record format.\n", passwdpath, lineno);
	    continue;
	}
	*cp++ = '\0';

	if ((cp = strchr(cp, ':')) == NULL) {
	    fprintf(stderr, "%s: line %d: invalid record format.\n", passwdpath, lineno);
	    continue;
	}
	*cp++ = '\0';

	if (strcmp(accessgroup, w)) {
	    fputs(line, tfp);
	    continue;
	}
	else {
	    if (delete) {
		if (!confirmed(accessgroup))
		    terminate();
	    }
	    else {
		if (realgroup[0] == '\0') {
		    strlcpy(realgroup, cp, BUFLEN);
		    if ((cp = strchr(realgroup, '\n')) != NULL)
			*cp = '\0';
		}
		addrecord(accessgroup, realgroup, sizeof(realgroup), "Updating accessgroup", tfp);
	    }
	    found = 1;
	}
    }

    if (!found && !delete)
	addrecord(accessgroup, realgroup, sizeof(realgroup), "Adding accessgroup", tfp);
    else if (!found && delete) {
	fprintf(stderr, "%s not found in %s.\n", accessgroup, passwdpath);
	terminate();
    }

    fclose(fp);
    fclose(tfp);

    command[0] = "cp";
    command[1] = tmp;
    command[2] = passwdpath;
    command[3] = NULL;

    cp_pid = fork();
    if(cp_pid==0) /* child -> execvp() cp */
        execvp("/bin/cp", command);
    else {
	int status;
	waitpid(cp_pid, &status, 0);
    }
    (void) unlink(tmp);
    exit (EXIT_SUCCESS);
}

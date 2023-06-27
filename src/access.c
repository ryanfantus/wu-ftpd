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
 
  $Id: access.c,v 1.9 2011/10/20 22:58:10 wmaton Exp $
 
****************************************************************************/
#include "config.h"

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>

#if defined(HAVE_SYS_SYSLOG_H)
#  include <sys/syslog.h>
#endif /* defined(HAVE_SYS_SYSLOG_H) */ 
#if defined(HAVE_SYSLOG_H) || (!defined(AUTOCONF) && !defined(HAVE_SYS_SYSLOG_H))
#  include <syslog.h>
#endif /* defined(HAVE_SYSLOG_H) || (!defined(AUTOCONF) && !defined(HAVE_SYS_SYSLOG_H)) */ 

#if defined(TIME_WITH_SYS_TIME)
#  include <time.h>
#  include <sys/time.h>
#  elif defined(HAVE_SYS_TIME_H)
#  include <sys/time.h>
#else /* !(defined(TIME_WITH_SYS_TIME)) */ 
#  include <time.h>
#endif /* !(defined(TIME_WITH_SYS_TIME)) */ 

#include <ctype.h>
#include <pwd.h>
#include <grp.h>
#include <limits.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <sys/param.h>

#if defined(HAVE_PATHS_H)
#  include <paths.h>
#endif /* defined(HAVE_PATHS_H) */ 

#include "pathnames.h"
#include "extensions.h"
#include "proto.h"

#if defined(HAVE_FCNTL_H)
#  include <fcntl.h>
#endif /* defined(HAVE_FCNTL_H) */ 

#if defined(OTHER_PASSWD)
#  include "getpwnam.h"
extern char _path_passwd[];
#  if defined(SHADOW_PASSWORD)
extern char _path_shadow[];
#  endif /* defined(SHADOW_PASSWORD) */ 
#endif /* defined(OTHER_PASSWD) */ 

#if defined(USE_PAM) && defined(OTHER_PASSWD)
extern int use_pam;
#endif /* defined(USE_PAM) && defined(OTHER_PASSWD) */ 

extern char remotehost[], remoteaddr[], *remoteident, *aclbuf;
extern int nameserved, anonymous, guest, TCPwindowsize, use_accessfile;
extern mode_t defumask;
extern struct SOCKSTORAGE his_addr;
char Shutdown[MAXPATHLEN];
int keepalive = 0;
#define MAXLINE	80
static char incline[MAXLINE];
static int pidfd = -1;
static int ripfd = -1;
static int hostslot = -1;
extern int Bypass_PID_Files;
extern int Bypass_RIP_Files;

#if !defined(HELP_CRACKERS)
extern char DelayedMessageFile[];
#endif /* !defined(HELP_CRACKERS) */ 

#include "wu_fnmatch.h"

#define ACL_COUNT	0
#define ACL_JOIN	1
#define ACL_REMOVE	2

/*************************************************************************/
/* FUNCTION  : parse_time                                                */
/* PURPOSE   : Check a single valid-time-string against the current time */
/*             and return whether or not a match occurs.                 */
/* ARGUMENTS : Pointer to the time-string.                               */
/*************************************************************************/

int parsetime(char *whattime)
{
    static char *days[] =
    {"Su", "Mo", "Tu", "We", "Th", "Fr", "Sa", "Wk"};
    time_t clock;
    struct tm *curtime;
    int wday, start, stop, ltime, validday, loop, match;

    (void) time(&clock);
    curtime = localtime(&clock);
    wday = curtime->tm_wday;
    validday = 0;
    match = 1;

    while (match && isalpha(*whattime) && isupper(*whattime)) {
	match = 0;
	for (loop = 0; loop < 8; loop++) {
	    if (strncmp(days[loop], whattime, 2) == 0) {
		whattime += 2;
		match = 1;
		if ((wday == loop) || ((loop == 7) && wday && (wday < 6))) {
		    validday = 1;
		}
	    }
	}
    }

    if (!validday) {
	if (strncmp(whattime, "Any", 3) == 0) {
	    validday = 1;
	    whattime += 3;
	}
	else
	    return (0);
    }

    if (sscanf(whattime, "%d-%d", &start, &stop) == 2) {
	ltime = curtime->tm_min + 100 * curtime->tm_hour;
	if ((start < stop) && ((ltime >= start) && ltime < stop))
	    return (1);
	if ((start > stop) && ((ltime >= start) || ltime < stop))
	    return (1);
    }
    else
	return (1);

    return (0);
}

/*************************************************************************/
/* FUNCTION  : validtime                                                 */
/* PURPOSE   : Break apart a set of valid time-strings and pass them to  */
/*             parse_time, returning whether or not ANY matches occurred */
/* ARGUMENTS : Pointer to the time-string                                */
/*************************************************************************/

int validtime(char *ptr)
{
    char *nextptr;
    int good;

    while (1) {
	nextptr = strchr(ptr, '|');
	if (strchr(ptr, '|') == NULL)
	    return (parsetime(ptr));
	*nextptr = '\0';
	good = parsetime(ptr);
	/* gotta restore the | or things get skipped! */
	*nextptr++ = '|';
	if (good)
	    return (1);
	ptr = nextptr;
    }
}

#if defined(INET6)
/*************************************************************************/
/* FUNCTION  : ipv6str                                                   */
/* PURPOSE   : Convert an IPv6 address string with optional /CIDR suffix */
/*             into an IPv6 address and a CIDR, which are returned in    */
/*             the arguments pointed to by in6p and cidrp.               */
/* ARGUMENTS : The IPv6 address string and pointers to in6_addr and CIDR */
/* RETURNS   : 1 if addr is an IPv6 address string, 0 if not             */
/*************************************************************************/

static int ipv6str(char *addr, struct in6_addr *in6p, int *cidrp)
{
    int cidr = 128;	/* IPv6 addresses are 128-bits long */
    char *ptr;

    if ((ptr = strstr(addr, "/")))
	*ptr = '\0';

    if (inet_pton(AF_INET6, addr, in6p) != 1) {
	if (ptr)
	    *ptr = '/';
	return 0;
    }

    if (ptr) {
	*ptr++ = '/';
	cidr = atoi(ptr);
	if (cidr < 0)
	    cidr = 0;
	else if (cidr > 128)
	    cidr = 128;
    }
    *cidrp = cidr;
    return 1;
}
#endif /* defined(INET6) */ 

/*************************************************************************/
/* FUNCTION  : hostmatch                                                 */
/* PURPOSE   : Match remote hostname or address against a glob string.   */
/* ARGUMENTS : The string to match, remote address, remote hostname.     */
/* RETURNS   : 0 if no match, 1 if a match occurs                        */
/*************************************************************************/

int hostmatch(char *addr, char *remoteaddr, char *remotehost)
{
    FILE *incfile;
    char *ptr, junk, s[4][4];
    int found = 1;
    int not_found = 0;
    int match = 0;
    int i, a[4], m[4], r[4], cidr;
#if defined(INET6)
    struct in6_addr addr_in6;
#endif /* defined(INET6) */ 

    if (addr == NULL)
	return (0);

    if (*addr == '!') {
	found = 0;
	not_found = 1;
	addr++;
    }

    if (sscanf(addr, "%d.%d.%d.%d/%d", a, a + 1, a + 2, a + 3, &cidr) == 5) {
	m[0] = 0;
	m[1] = 0;
	m[2] = 0;
	m[3] = 0;
	if (cidr < 0)
	    cidr = 0;
	else if (cidr > 32)
	    cidr = 32;
	for (i = 0; cidr > 8; i++) {
	    m[i] = 255;
	    cidr -= 8;
	}
	switch (cidr) {
	case 8:
	    m[i] += 1;
	case 7:
	    m[i] += 2;
	case 6:
	    m[i] += 4;
	case 5:
	    m[i] += 8;
	case 4:
	    m[i] += 16;
	case 3:
	    m[i] += 32;
	case 2:
	    m[i] += 64;
	case 1:
	    m[i] += 128;
	}
	/* make sure remoteaddr is an IPv4 address */
	if (sscanf(remoteaddr, "%d.%d.%d.%d", r, r + 1, r + 2, r + 3) != 4)
	    return not_found;
	for (i = 0; i < 4; i++)
	    if ((a[i] & m[i]) != (r[i] & m[i]))
		return not_found;
	return found;
    }
    else if (sscanf(addr, "%d.%d.%d.%d:%d.%d.%d.%d", a, a + 1, a + 2, a + 3, m, m + 1, m + 2, m + 3) == 8) {
	/* make sure remoteaddr is an IPv4 address */
	if (sscanf(remoteaddr, "%d.%d.%d.%d", r, r + 1, r + 2, r + 3) != 4)
	    return not_found;
	for (i = 0; i < 4; i++)
	    if ((a[i] & m[i]) != (r[i] & m[i]))
		return not_found;
	return found;
    }
    else if (sscanf(addr, "%3[0-9*].%3[0-9*].%3[0-9*].%3[0-9*]%c",
		    s[0], s[1], s[2], s[3], &junk) == 4 &&
	    (!strcmp(s[0],"*") || !strchr(s[0],'*')) &&
	    (!strcmp(s[1],"*") || !strchr(s[1],'*')) &&
	    (!strcmp(s[2],"*") || !strchr(s[2],'*')) &&
	    (!strcmp(s[3],"*") || !strchr(s[3],'*'))  ) {
	/* make sure remoteaddr is an IPv4 address */
	if (sscanf(remoteaddr, "%d.%d.%d.%d", r, r + 1, r + 2, r + 3) != 4)
	    return not_found;
	for (i = 0; i < 4; i++)
	    if ((strcmp(s[i],"*")) && (atoi(s[i]) != r[i]))
		return not_found;
	return found;
    }
#if defined(INET6)
    else if (ipv6str(addr, &addr_in6, &cidr)) {
	struct in6_addr rem_in6;
	uint32_t addr32[4], rem32[4];
	int bitstozero;

	if (inet_pton6(remoteaddr, &rem_in6) != 1)
	    return not_found;

	memcpy(addr32, addr_in6.s6_addr, sizeof(addr32));
	memcpy(rem32, rem_in6.s6_addr, sizeof(rem32));

	/* IPv6 addresses are 128-bits long */
	bitstozero = 128 - cidr;

	/* zero bits starting with the least significant */
	for (i = 3; (bitstozero > 0) && (i >= 0); i--, bitstozero -= 32) {
	    if (bitstozero >= 32)
		addr32[i] = rem32[i] = 0;
	    else {
		addr32[i] = (ntohl(addr32[i]) >> bitstozero) << bitstozero;
		rem32[i] = (ntohl(rem32[i]) >> bitstozero) << bitstozero;
	    }
	}
	if (memcmp(addr32, rem32, sizeof(addr32)))
	    return not_found;
	return found;
    }
#endif /* defined(INET6) */ 
    else if (*addr == '/') {
	/*
	 * read addrglobs from named path using similar format as addrglobs
	 * in access file
	 */
	if ((incfile = fopen(addr, "r")) == NULL) {
	    if (errno != ENOENT)
		syslog(LOG_ERR,
		       "cannot open addrglob file %s: %m", addr);
	    return (0);
	}

	while (!match && (fgets(incline, MAXLINE, incfile) != NULL)) {
	    ptr = strtok(incline, " \t\n");
	    if (ptr && hostmatch(ptr, remoteaddr, remotehost))
		match = 1;
	    while (!match && ((ptr = strtok(NULL, " \t\n")) != NULL)) {
		if (ptr && hostmatch(ptr, remoteaddr, remotehost))
		    match = 1;
	    }
	}
	fclose(incfile);
	return (match ? found : not_found);
    }
    else {			/* match a hostname or hostname glob */
	match = (!wu_fnmatch(addr, remotehost, FNM_CASEFOLD)) ||
		(!wu_fnmatch(addr, remoteaddr, 0));
	return (match ? found : not_found);
    }
}

/*************************************************************************/
/* FUNCTION  : acl_guestgroup                                            */
/* PURPOSE   : If the real user is a member of any of the listed groups, */
/*             return 1.  Otherwise return 0.                            */
/* ARGUMENTS : pw, a pointer to the passwd struct for the user.          */
/*************************************************************************/

int acl_guestgroup(struct passwd *pw)
{
    /*
     * guestuser <name> [<name> ...]
     *
     * If name begins with '%' treat as numeric.
     * Numeric names may be ranges.
     *   %<uid>       A single numeric UID
     *   %<uid>+      All UIDs greater or equal to UID
     *   %<uid>-      All UIDs greater or equal to UID
     *   %-<uid>      All UIDs less or equal to UID
     *   %<uid>-<uid> All UIDs between the two (inclusive)
     *   *            All UIDs
     */

    if (anonymous)
	return (0);

    if (uid_match("guestuser", pw->pw_uid))
	return (1);

    /*
     * guestgroup <group> [<group> ...]
     *
     * If group begins with '%' treat as numeric.
     * Numeric groups may be ranges.
     *   %<gid>       A single GID
     *   %<gid>+      All GIDs greater or equal to GID
     *   %<gid>-      All GIDs greater or equal to GID
     *   %-<gid>      All GIDs less or equal to GID
     *   %<gid>-<gid> All GIDs between the two (inclusive)
     *   *            All GIDs
     */
    if (gid_match("guestgroup", pw->pw_gid, pw->pw_name))
	return (1);

    return (0);
}

int acl_realgroup(struct passwd *pw)
{
    /*
     * realuser <name> [<name> ...]
     *
     * If name begins with '%' treat as numeric.
     * Numeric names may be ranges.
     *   %<uid>       A single numeric UID
     *   %<uid>+      All UIDs greater or equal to UID
     *   %<uid>-      All UIDs greater or equal to UID
     *   %-<uid>      All UIDs less or equal to UID
     *   %<uid>-<uid> All UIDs between the two (inclusive)
     *   *            All UIDs
     */

    if (anonymous)
	return (0);

    if (uid_match("realuser", pw->pw_uid))
	return (1);

    /*
     * realgroup <group> [<group> ...]
     *
     * If group begins with '%' treat as numeric.
     * Numeric groups may be ranges.
     *   %<gid>       A single GID
     *   %<gid>+      All GIDs greater or equal to GID
     *   %<gid>-      All GIDs greater or equal to GID
     *   %-<gid>      All GIDs less or equal to GID
     *   %<gid>-<gid> All GIDs between the two (inclusive)
     *   *            All GIDs
     */
    if (gid_match("realgroup", pw->pw_gid, pw->pw_name))
	return (1);

    return (0);
}

/*************************************************************************/
/* FUNCTION  : acl_autogroup                                             */
/* PURPOSE   : If the guest user is a member of any of the classes in    */
/*             the autogroup comment, cause a setegid() to the specified */
/*             group.                                                    */
/* ARGUMENTS : pw, a pointer to the passwd struct for the user.          */
/*************************************************************************/

void acl_autogroup(struct passwd *pw)
{
    char class[1024];

    struct aclmember *entry = NULL;
    struct group *grp;
    int which;

    (void) acl_getclass(class, sizeof(class));

    /* autogroup <group> <class> [<class> ...] */
    while (getaclentry("autogroup", &entry)) {
	if (!ARG0 || !ARG1)
	    continue;
	for (which = 1; (which < MAXARGS) && ARG[which]; which++) {
	    if (!strcasecmp(ARG[which], class)) {
		if (ARG0[0] == '%')
		    pw->pw_gid = atoi(ARG0 + 1);
		else {
		    if ((grp = getgrnam(ARG0)))
			pw->pw_gid = grp->gr_gid;
		    else
			syslog(LOG_ERR, "autogroup: set group %s not found", ARG0);
		    endgrent();
		}
		return;
	    }
	}
    }
}

/*************************************************************************/
/* FUNCTION  : acl_setfunctions                                          */
/* PURPOSE   : Scan the ACL buffer and determine what logging to perform */
/*             for this user, and whether or not user is allowed to use  */
/*             the automatic TAR and COMPRESS functions.                 */
/* ARGUMENTS : None                                                      */
/*************************************************************************/

void acl_setfunctions(void)
{
    char class[1024];
    struct aclmember *entry = NULL;
    int inbound = 0, outbound = 0, which, set;
    extern int log_incoming_xfers, log_outbound_xfers, mangleopts, log_commands,
	log_security, syslogmsg, lgi_failure_threshold;

    log_security = 0;
    mangleopts = 0;

    /* Initialize to the logging value specified on the command line, can't
       just use the current value as it may have been set by a previous call. */
    log_incoming_xfers = (log_incoming_xfers & 2) ? 3 : 0;
    log_outbound_xfers = (log_outbound_xfers & 2) ? 3 : 0;
    log_commands = (log_commands & 2) ? 3 : 0;

    (void) acl_getclass(class, sizeof(class));

    if (getaclentry("loginfails", &entry)) {
	if (ARG0)
	    lgi_failure_threshold = atoi(ARG0);
    }
#if !defined(NO_PRIVATE)
    entry = (struct aclmember *) NULL;
    if (getaclentry("private", &entry)
    && ARG0
    && !strcasecmp(ARG0, "yes"))
	priv_setup(_path_private);
#endif /* !defined(NO_PRIVATE) */ 

    entry = (struct aclmember *) NULL;
    set = 0;
    while (!set && getaclentry("compress", &entry))
	if (!ARG0)
	    set = 1;
	else if (!strcasecmp(ARG0, "yes")) {
	    if (!ARG1)
		set = 1;
	    else
		for (which = 1; (which < MAXARGS) && ARG[which]; which++)
		    if (!wu_fnmatch(ARG[which], class, FNM_CASEFOLD)) {
			set = 1;
			break;
		    }
	}
    if (set)
	mangleopts |= (O_COMPRESS | O_UNCOMPRESS);

    entry = (struct aclmember *) NULL;
    set = 0;
    while (!set && getaclentry("tar", &entry))
	if (!ARG0)
	    set = 1;
	else if (!strcasecmp(ARG0, "yes")) {
	    if (!ARG1)
		set = 1;
	    else
		for (which = 1; (which < MAXARGS) && ARG[which]; which++)
		    if (!wu_fnmatch(ARG[which], class, FNM_CASEFOLD)) {
			set = 1;
			break;
		    }
	}
    if (set)
	mangleopts |= O_TAR;

    /* plan on expanding command syntax to include classes for each of these */

    entry = (struct aclmember *) NULL;
    while (getaclentry("log", &entry)) {
	if (ARG0 && !strcasecmp(ARG0, "commands")) {
	    if (!ARG1)
		log_commands |= 1;
	    else {
		if (anonymous && strcasestr(ARG1, "anonymous"))
		    log_commands |= 1;
		if (guest && strcasestr(ARG1, "guest"))
		    log_commands |= 1;
		if (!guest && !anonymous && strcasestr(ARG1, "real"))
		    log_commands |= 1;
	    }
	}
	if (ARG0 && !strcasecmp(ARG0, "transfers")) {
	    set = 0;
	    if (!ARG1) {
		set = 1;
		inbound = 1;
		outbound = 1;
	    }
	    else {
		if (strcasestr(ARG1, "anonymous") && anonymous)
		    set = 1;
		if (strcasestr(ARG1, "guest") && guest)
		    set = 1;
		if (strcasestr(ARG1, "real") && !guest && !anonymous)
		    set = 1;
		if (!ARG2) {
		    inbound = 1;
		    outbound = 1;
		}
		else {
		    if (strcasestr(ARG2, "inbound"))
			inbound = 1;
		    if (strcasestr(ARG2, "outbound"))
			outbound = 1;
		}
	    }
	    if (set)
		log_incoming_xfers |= inbound;
	    if (set)
		log_outbound_xfers |= outbound;
	}
	if (ARG0 && !strcasecmp(ARG0, "security")) {
	    if (!ARG1)
		log_security = 1;
	    else {
		if (strcasestr(ARG1, "anonymous") && anonymous)
		    log_security = 1;
		if (strcasestr(ARG1, "guest") && guest)
		    log_security = 1;
		if (strcasestr(ARG1, "real") && !guest && !anonymous)
		    log_security = 1;
	    }
	}
	if (ARG0) {
	    if (!strcasecmp(ARG0, "syslog"))
		syslogmsg = 1;
	    if (!strcasecmp(ARG0, "xferlog"))
		syslogmsg = 0;
	    if (!strcasecmp(ARG0, "syslog+xferlog")
	    ||  !strcasecmp(ARG0, "xferlog+syslog"))
		syslogmsg = 2;
	}
    }
}

/*************************************************************************/
/* FUNCTION  : acl_getclass                                              */
/* PURPOSE   : Scan the ACL buffer and determine what class user is in.  */
/* ARGUMENTS : Pointer to buffer into which the class name is copied,    */
/*             length of the buffer.                                     */
/*************************************************************************/

int acl_getclass(char *classbuf, size_t clen)
{
    int which;
    struct aclmember *entry = NULL;

    while (getaclentry("class", &entry)) {
	if (ARG0)
	    strlcpy(classbuf, ARG0, clen);

	for (which = 2; (which < MAXARGS) && ARG[which]; which++) {
	    if (anonymous && strcasestr(ARG1, "anonymous") &&
		hostmatch(ARG[which], remoteaddr, remotehost))
		return (1);

	    if (guest && strcasestr(ARG1, "guest") && hostmatch(ARG[which], remoteaddr, remotehost))
		return (1);

	    if (!guest && !anonymous && strcasestr(ARG1, "real") &&
		hostmatch(ARG[which], remoteaddr, remotehost))
		return (1);
	}
    }

    *classbuf = (char) NULL;
    return (0);
}

/*************************************************************************/
/* FUNCTION  : acl_getlimit                                              */
/* PURPOSE   : Scan the ACL buffer and determine what limit applies to   */
/*             the user.                                                 */
/* ARGUMENTS : Pointer to class name, pointer to buffer into which the   */
/*             path of the message file is copied, length of buffer.     */
/*************************************************************************/

int acl_getlimit(char *class, char *msgpathbuf, size_t mlen)
{
    int limit;
    struct aclmember *entry = NULL;

    if (msgpathbuf)
	*msgpathbuf = '\0';

    /* limit <class> <n> <times> [<message_file>] */
    while (getaclentry("limit", &entry)) {
	if (!ARG0 || !ARG1 || !ARG2)
	    continue;
	if (!strcasecmp(class, ARG0)) {
	    limit = atoi(ARG1);
	    if (validtime(ARG2)) {
		if (ARG3 && msgpathbuf)
		    strlcpy(msgpathbuf, ARG3, mlen);
		return (limit);
	    }
	}
    }
    return (-1);
}

/*************************************************************************/
/* FUNCTION  : acl_gethostlimit                                          */
/* PURPOSE   : Scan the ACL buffer and determine what host limit applies */
/*             to the user.                                              */
/* ARGUMENTS : Pointer to class name, pointer to buffer into which the   */
/*             path of the message file is copied, length of buffer.     */
/*************************************************************************/

static int acl_gethostlimit(char *class, char *msgpathbuf, size_t mlen)
{
    int limit;
    struct aclmember *entry = NULL;

    if (msgpathbuf)
	*msgpathbuf = '\0';

    /* host-limit <class> <n> <times> [<message_file>] */
    while (getaclentry("host-limit", &entry)) {
	if (!ARG0 || !ARG1 || !ARG2)
	    continue;
	if (!strcasecmp(class, ARG0)) {
	    limit = atoi(ARG1);
	    if (validtime(ARG2)) {
		if (ARG3 && msgpathbuf)
		    strlcpy(msgpathbuf, ARG3, mlen);
		return (limit);
	    }
	}
    }
    return (-1);
}

/*************************************************************************/
/* FUNCTION  : acl_getnice                                               */
/* PURPOSE   : Scan the ACL buffer and determine what nice value applies */
/*             to the user.                                              */
/* ARGUMENTS : Pointer to class name.                                    */
/*************************************************************************/

void acl_getnice(char *class)
{
    int nice_delta_for_class_found = 0;
    int default_nice_delta = 0;
    struct aclmember *entry = NULL;
    extern int nice_delta;

    nice_delta = 0;

    /* nice <nice_delta> [<class>] */
    while (getaclentry("nice", &entry)) {
	if (!ARG0)
	    continue;
	if (!ARG1)
	    default_nice_delta = atoi(ARG0);
	else if (!strcasecmp(class, ARG1)) {
	    nice_delta_for_class_found = 1;
	    nice_delta = atoi(ARG0);
	}
    }
    if (!nice_delta_for_class_found)
	nice_delta = default_nice_delta;
}


/*************************************************************************/
/* FUNCTION  : acl_getdefumask                                           */
/* PURPOSE   : Scan the ACL buffer to determine what umask value applies */
/*             to the user.                                              */
/* ARGUMENTS : Pointer to class name.                                    */
/*************************************************************************/

void acl_getdefumask(char *class)
{
    static int firsttime = 1;
    static mode_t initumask;
    struct aclmember *entry = NULL;
    char *ptr;
    unsigned int val;

    if (firsttime) {
	initumask = defumask;
	firsttime = 0;
    }
    else
	defumask = initumask;

    /* defumask <umask> [<class>] */
    while (getaclentry("defumask", &entry)) {
	if (!ARG0)
	    continue;
	if (!ARG1 || !strcasecmp(class, ARG1)) {
	    ptr = ARG0;
	    val = 0;
	    while (*ptr && *ptr >= '0' && *ptr <= '7')
		val = val * 8 + *ptr++ - '0';
	    if (!*ptr && val <= 0777) {
		defumask = val;
		if (ARG1)
		    break;
	    }
	    else
		syslog(LOG_WARNING, "bad umask in %s ignored: defumask %s",
		       _path_ftpaccess, ARG0);
	}
    }
    umask(defumask);
}

/*************************************************************************/
/* FUNCTION  : acl_tcpwindow                                             */
/* PURPOSE   : Scan the ACL buffer and determine what TCP window size to */
/*             use based upon the class.                                 */
/* ARGUMENTS : Pointer to class name.                                    */
/*************************************************************************/

void acl_tcpwindow(char *class)
{
    struct aclmember *entry = NULL;

    TCPwindowsize = 0;

    /* tcpwindow <size> [<class>] */
    while (getaclentry("tcpwindow", &entry)) {
	if (!ARG0)
	    continue;
	if (!ARG1)
	    TCPwindowsize = strtoul(ARG0, NULL, 0);
	else if (!strcasecmp(class, ARG1)) {
	    TCPwindowsize = strtoul(ARG0, NULL, 0);
	    break;
	}
    }
}

/*************************************************************************/
/* FUNCTION  : acl_bufsize                                               */
/* PURPOSE   : Scan the ACL buffer and determine the send and receive    */
/*             buffer sizes to use                                       */
/* ARGUMENTS : None                                                      */
/*************************************************************************/

static void acl_bufsize(void)
{
    struct aclmember *entry;
    extern size_t sendbufsz, recvbufsz;

    /* sendbuf <size> [<typelist>] */
    entry = (struct aclmember *) NULL;
    sendbufsz = 0;
    while (getaclentry("sendbuf", &entry)) {
	if (!ARG0)
	    continue;
	if (!ARG1)
	    sendbufsz = strtoul(ARG0, NULL, 0);
	else if (type_match(ARG1)) {
	    sendbufsz = strtoul(ARG0, NULL, 0);
	    break;
	}
    }

    /* recvbuf <size> [<typelist>] */
    entry = (struct aclmember *) NULL;
    recvbufsz = 0;
    while (getaclentry("recvbuf", &entry)) {
	if (!ARG0)
	    continue;
	if (!ARG1)
	    recvbufsz = strtoul(ARG0, NULL, 0);
	else if (type_match(ARG1)) {
	    recvbufsz = strtoul(ARG0, NULL, 0);
	    break;
	}
    }
}

#if defined(TRANSFER_COUNT)
#  if defined(TRANSFER_LIMIT)

/*************************************************************************/
/* FUNCTION  : acl_filelimit                                             */
/* PURPOSE   : Scan the ACL buffer and determine what file limit to use  */
/*             based upon the class.                                     */
/* ARGUMENTS : Pointer to class name.                                    */
/*************************************************************************/

void acl_filelimit(char *class)
{
    struct aclmember *entry = NULL;
    int raw_in = 0;
    int raw_out = 0;
    int raw_total = 0;
    int data_in = 0;
    int data_out = 0;
    int data_total = 0;
    extern int file_limit_raw_in, file_limit_raw_out, file_limit_raw_total;
    extern int file_limit_data_in, file_limit_data_out, file_limit_data_total;

    file_limit_raw_in = 0;
    file_limit_raw_out = 0;
    file_limit_raw_total = 0;
    file_limit_data_in = 0;
    file_limit_data_out = 0;
    file_limit_data_total = 0;

    /* file-limit [<raw>] <in|out|total> <count> [<class>] */
    while (getaclentry("file-limit", &entry)) {
	if (!ARG0 || !ARG1)
	    continue;
	if (!strcasecmp(ARG0, "raw")) {
	    if (!ARG2)
		continue;
	    if (!strcasecmp(ARG1, "in")) {
		if (!ARG3) {
		    if (!raw_in)
			file_limit_raw_in = atoi(ARG2);
		}
		else if (!strcasecmp(class, ARG3)) {
		    raw_in = 1;
		    file_limit_raw_in = atoi(ARG2);
		}
	    }
	    else if (!strcasecmp(ARG1, "out")) {
		if (!ARG3) {
		    if (!raw_out)
			file_limit_raw_out = atoi(ARG2);
		}
		else if (!strcasecmp(class, ARG3)) {
		    raw_out = 1;
		    file_limit_raw_out = atoi(ARG2);
		}
	    }
	    else if (!strcasecmp(ARG1, "total")) {
		if (!ARG3) {
		    if (!raw_total)
			file_limit_raw_total = atoi(ARG2);
		}
		else if (!strcasecmp(class, ARG3)) {
		    raw_total = 1;
		    file_limit_raw_total = atoi(ARG2);
		}
	    }
	}
	else if (!strcasecmp(ARG0, "in")) {
	    if (!ARG2) {
		if (!data_in)
		    file_limit_data_in = atoi(ARG1);
	    }
	    else if (!strcasecmp(class, ARG2)) {
		data_in = 1;
		file_limit_data_in = atoi(ARG1);
	    }
	}
	else if (!strcasecmp(ARG0, "out")) {
	    if (!ARG2) {
		if (!data_out)
		    file_limit_data_out = atoi(ARG1);
	    }
	    else if (!strcasecmp(class, ARG2)) {
		data_out = 1;
		file_limit_data_out = atoi(ARG1);
	    }
	}
	else if (!strcasecmp(ARG0, "total")) {
	    if (!ARG2) {
		if (!data_total)
		    file_limit_data_total = atoi(ARG1);
	    }
	    else if (!strcasecmp(class, ARG2)) {
		data_total = 1;
		file_limit_data_total = atoi(ARG1);
	    }
	}
    }
}

/*************************************************************************/
/* FUNCTION  : acl_datalimit                                             */
/* PURPOSE   : Scan the ACL buffer and determine what data limit to use  */
/*             based upon the class.                                     */
/* ARGUMENTS : Pointer to class name.                                    */
/*************************************************************************/

void acl_datalimit(char *class)
{
    struct aclmember *entry = NULL;
    int raw_in = 0;
    int raw_out = 0;
    int raw_total = 0;
    int data_in = 0;
    int data_out = 0;
    int data_total = 0;
    extern off_t data_limit_raw_in, data_limit_raw_out, data_limit_raw_total;
    extern off_t data_limit_data_in, data_limit_data_out, data_limit_data_total;

    data_limit_raw_in = 0;
    data_limit_raw_out = 0;
    data_limit_raw_total = 0;
    data_limit_data_in = 0;
    data_limit_data_out = 0;
    data_limit_data_total = 0;

    /* data-limit [<raw>] <in|out|total> <count> [<class>] */
    while (getaclentry("data-limit", &entry)) {
	if (!ARG0 || !ARG1)
	    continue;
	if (!strcasecmp(ARG0, "raw")) {
	    if (!ARG2)
		continue;
	    if (!strcasecmp(ARG1, "in")) {
		if (!ARG3) {
		    if (!raw_in)
			data_limit_raw_in = atoi(ARG2);
		}
		else if (!strcasecmp(class, ARG3)) {
		    raw_in = 1;
		    data_limit_raw_in = atoi(ARG2);
		}
	    }
	    else if (!strcasecmp(ARG1, "out")) {
		if (!ARG3) {
		    if (!raw_out)
			data_limit_raw_out = atoi(ARG2);
		}
		else if (!strcasecmp(class, ARG3)) {
		    raw_out = 1;
		    data_limit_raw_out = atoi(ARG2);
		}
	    }
	    else if (!strcasecmp(ARG1, "total")) {
		if (!ARG3) {
		    if (!raw_total)
			data_limit_raw_total = atoi(ARG2);
		}
		else if (!strcasecmp(class, ARG3)) {
		    raw_total = 1;
		    data_limit_raw_total = atoi(ARG2);
		}
	    }
	}
	else if (!strcasecmp(ARG0, "in")) {
	    if (!ARG2) {
		if (!data_in)
		    data_limit_data_in = atoi(ARG1);
	    }
	    else if (!strcasecmp(class, ARG2)) {
		data_in = 1;
		data_limit_data_in = atoi(ARG1);
	    }
	}
	else if (!strcasecmp(ARG0, "out")) {
	    if (!ARG2) {
		if (!data_out)
		    data_limit_data_out = atoi(ARG1);
	    }
	    else if (!strcasecmp(class, ARG2)) {
		data_out = 1;
		data_limit_data_out = atoi(ARG1);
	    }
	}
	else if (!strcasecmp(ARG0, "total")) {
	    if (!ARG2) {
		if (!data_total)
		    data_limit_data_total = atoi(ARG1);
	    }
	    else if (!strcasecmp(class, ARG2)) {
		data_total = 1;
		data_limit_data_total = atoi(ARG1);
	    }
	}
    }
}


#    if defined(RATIO)

/*************************************************************************/
/* FUNCTION  : acl_downloadrate                                          */
/* PURPOSE   : Scan the ACL buffer and determine what data limit to use  */
/*             based upon the class.                                     */
/* ARGUMENTS : Pointer to class name.                                    */
/*************************************************************************/

void acl_downloadrate(char *class)
{
    struct aclmember *entry = NULL;
    extern int upload_download_rate;
    int which;

    upload_download_rate = 0;

    /* ul-dl-rate <rate> [<class> ...] */
    while (getaclentry("ul-dl-rate", &entry)) {
	if (!ARG0 )
	    continue;

	if (!ARG1) {
	    upload_download_rate = atol(ARG0);
	}
	else {
	    for (which = 1; (which < MAXARGS) && ARG[which]; which++) {
		if (!strcasecmp(ARG[which], class))
		    upload_download_rate = atol(ARG0);
	    }
	}

    }
}
#    endif /* defined(RATIO) */ 

#  endif /* defined(TRANSFER_LIMIT) */ 
#endif /* defined(TRANSFER_COUNT) */ 

/*************************************************************************/
/* FUNCTION  : acl_deny                                                  */
/* PURPOSE   : Scan the ACL buffer and determine if access is denied.    */
/* ARGUMENTS : Pointer to buffer into which the path of the message file */
/*             is copied, length of buffer.                              */
/*************************************************************************/

int acl_deny(char *msgpathbuf, size_t mlen)
{
    struct aclmember *entry = NULL;

    if (msgpathbuf)
	*msgpathbuf = (char) NULL;

    /* deny <addrglob> [<message_file>] */
    while (getaclentry("deny", &entry)) {
	if (!ARG0)
	    continue;
	if (strcasecmp(ARG0, "!nameserved") == 0) {
	    if (!nameserved) {
		if (ARG1)
		    strlcpy(msgpathbuf, entry->arg[1], mlen);
		return (1);
	    }
	}
	else if (hostmatch(ARG0, remoteaddr, remotehost)) {
	    if (ARG1)
		strlcpy(msgpathbuf, entry->arg[1], mlen);
	    return (1);
	}
    }
    return (0);
}

/*************************************************************************/
/* FUNCTION  : lock_fd                                                   */
/* PURPOSE   : Lock a file.                                              */
/* ARGUMENTS : File descriptor of file to lock, string indicating file   */
/*             being locked.                                             */
/*************************************************************************/

static void lock_fd(int fd, char *str)
{
#if !defined(HAVE_FLOCK)
    struct flock arg;
#endif /* !defined(HAVE_FLOCK) */ 

#if defined(HAVE_FLOCK)
    while (flock(fd, LOCK_EX)) {
#  if !defined(NO_PID_SLEEP_MSGS)
	syslog(LOG_ERR, "sleeping: flock of %s file failed: %m", str);
#  endif /* !defined(NO_PID_SLEEP_MSGS) */ 
#else /* !(defined(HAVE_FLOCK)) */ 
    arg.l_type = F_WRLCK;
    arg.l_whence = arg.l_start = arg.l_len = 0;
    while (-1 == fcntl(fd, F_SETLK, &arg)) {
#  if !defined(NO_PID_SLEEP_MSGS)
	syslog(LOG_ERR, "sleeping: fcntl lock of %s file failed: %m", str);
#  endif /* !defined(NO_PID_SLEEP_MSGS) */ 
#endif /* !(defined(HAVE_FLOCK)) */ 
	sleep(1);
    }
}

/*************************************************************************/
/* FUNCTION  : unlock_fd                                                 */
/* PURPOSE   : Unlock a file locked by lock_fd.                          */
/* ARGUMENTS : File descriptor of file to unlock.                        */
/*************************************************************************/

static void unlock_fd(int fd)
{
#if !defined(HAVE_FLOCK)
    struct flock arg;
#endif /* !defined(HAVE_FLOCK) */ 

#if defined(HAVE_FLOCK)
    flock(fd, LOCK_UN);
#else /* !(defined(HAVE_FLOCK)) */ 
    arg.l_type = F_UNLCK;
    arg.l_whence = arg.l_start = arg.l_len = 0;
    fcntl(fd, F_SETLK, &arg);
#endif /* !(defined(HAVE_FLOCK)) */ 
}

/*************************************************************************/
/* FUNCTION  : open_ripfile                                              */
/* PURPOSE   : Return a file descriptor of an opened RIP file.           */
/* ARGUMENTS : Users class.                                              */
/*************************************************************************/

static int open_ripfile(char *class)
{
    int fd;
    mode_t oldmask;
    char ripfile[MAXPATHLEN];

    snprintf(ripfile, sizeof(ripfile), _PATH_RIPNAMES, class);
    oldmask = umask(0);
    fd = open(ripfile, O_RDWR | O_CREAT, 0644);
    (void) umask(oldmask);
    if (fd < 0)
	syslog(LOG_ERR, "cannot open rip file %s: %m", ripfile);
    return (fd);
}

/*************************************************************************/
/* FUNCTION  : acl_addhost                                               */
/* PURPOSE   : Add the remote host IP to the list of addresses in the    */
/*             specified class.                                          */
/* ARGUMENTS : The name of the class, host limit for the class.          */
/* RETURNS   : 0 on success, -1 on failure                               */
/*************************************************************************/

static int acl_addhost(char *class, int limit)
{
    int count = 0, slot = 0, n, which;
#if defined(INET6)
    struct in6_addr buf[1024];
    struct in6_addr *remaddr, addr;
    struct in6_addr empty;
#else /* !(defined(INET6)) */ 
    struct in_addr buf[1024];
    struct in_addr *remaddr;
    struct in_addr empty;
#endif /* !(defined(INET6)) */ 

    if (Bypass_RIP_Files)
	return (0);

    /*
     * if ripfd was not opened previously...
     * ripfd must stay open after the chroot(~ftp)
     */
    if (ripfd < 0) {
	if ((ripfd = open_ripfile(class)) < 0)
	    return (-1);
    }

    memset(&empty, 0, sizeof(empty));

#if defined(INET6)
    if (SOCK_FAMILY(his_addr) == AF_INET6)
	remaddr = &((struct sockaddr_in6 *)&(his_addr))->sin6_addr;
    else {
	/* Convert into an IPv4-mapped IPv6 address for use in the rip file */
	remaddr = &addr;
	(void) inet_pton6(remoteaddr, remaddr);
    }
#else /* !(defined(INET6)) */ 
    remaddr = &his_addr.sin_addr;
#endif /* !(defined(INET6)) */ 

    lock_fd(ripfd, "rip");
    lseek(ripfd, (off_t)0, SEEK_SET);
    while ((n = read(ripfd, (void *)buf, sizeof(buf))) > 0) {
	n = n / sizeof(*remaddr);
	for (which = 0; which < n; which++, slot++) {
	    if (memcmp(remaddr, &buf[which], sizeof(*remaddr)) == 0)
		count++;
	    else {
		if ((hostslot == -1) &&
		    (memcmp(&empty, &buf[which], sizeof(empty))) == 0)
		    hostslot = slot;
	    }
	}
    }
    if (hostslot == -1)
	hostslot = slot;

    if ((limit != -1) && (count >= limit)) {
	/* no need to leave the rip file open as we were not added to it */
	unlock_fd(ripfd);
	close(ripfd);
	ripfd = -1;
	hostslot = -1;
	return(-1);
    }
    lseek(ripfd, (off_t)hostslot*sizeof(*remaddr), SEEK_SET);
    write(ripfd, remaddr, sizeof(*remaddr));
    unlock_fd(ripfd);
    /* ripfd left open so can be updated after a chroot */
    return (0);
}

/*************************************************************************/
/* FUNCTION  : acl_remhost                                               */
/* PURPOSE   : Remove the remote host IP from the list of addresses in   */
/*             our class.                                                */
/*************************************************************************/

static void acl_remhost()
{
#if defined(INET6)
    struct in6_addr empty;
#else /* !(defined(INET6)) */ 
    struct in_addr empty;
#endif /* !(defined(INET6)) */ 

    if (ripfd < 0)
	return;

    memset(&empty, 0, sizeof(empty));
    lock_fd(ripfd, "rip");
    lseek(ripfd, (off_t)hostslot*sizeof(empty), SEEK_SET);
    write(ripfd, &empty, sizeof(empty));
    unlock_fd(ripfd);
    close(ripfd);
    ripfd = -1;
    hostslot = -1;
}

/*************************************************************************/
/* FUNCTION  : limit_op                                                  */
/* PURPOSE   : Carry out the specified limit operation, returning the    */
/*             number of users in the class or -1 on failure.            */
/* ARGUMENTS : Operation (ACL_COUNT/ACL_JOIN/ACL_REMOVE), user limit     */
/*************************************************************************/

static int limit_op(int operation, int limit)
{
    int i, j, n, count;
    int bit_changed, toomany, write_all_header;
    off_t offset;
    pid_t pid, procid;
    time_t now;
    struct pidfile_header hdr;
    unsigned char bits, buf[1024];

    if (pidfd < 0)
	return (-1);

    if (lseek(pidfd, (off_t)0, SEEK_SET) != 0)
	return (-1);

    if (operation == ACL_COUNT) {
	lock_fd(pidfd, "pid");
	n = read(pidfd, (void *)&hdr.count, sizeof(hdr.count));
	unlock_fd(pidfd);
	if (n != sizeof(hdr.count))
	    return (-1);
	return (hdr.count);
    }

    toomany = 0;
    write_all_header = 0;
    lock_fd(pidfd, "pid");
    if (read(pidfd, (void *)&hdr, sizeof(hdr)) != sizeof(hdr)) {
	hdr.count = 0;
	hdr.last_checked = 0;
    }
    now = time(NULL);

    /* check bitmap accuracy and re-calculate the count every 15 minutes */
    if ((now >= (hdr.last_checked + (15 * 60))) || (now < hdr.last_checked)) {
	count = 0;
	procid = 0;
	bit_changed = 0;
	while ((n = read(pidfd, (void *)buf, sizeof(buf))) > 0) {
	    for (i = 0; i < n; i++) {
		if (buf[i] == 0) {
		    procid += CHAR_BIT;
		}
		else {
		    bits = 1;
		    for (j = 0; j < CHAR_BIT; j++) {
			if ((buf[i] & bits) != 0) {
			    if (kill(procid, 0) == 0) {
				count++;
			    }
			    else {
				bit_changed = 1;
				buf[i] &= ~bits;
			    }
			}
			bits <<= 1;
			procid++;
		    }
		}
	    }
	    if (bit_changed) {
		lseek(pidfd, (off_t)-n, SEEK_CUR);
		write(pidfd, (void *)buf, n);
		bit_changed = 0;
	    }
	}
	if (hdr.count != count) {
	    syslog(LOG_INFO, "pid file header count (%d) corrected to %d",
		   hdr.count, count);
	    hdr.count = count;
	}
	hdr.last_checked = time(NULL);
	write_all_header = 1;
    }

    /* limit set to -1 when no limit defined */
    if ((operation == ACL_JOIN) && (limit != -1) && (hdr.count >= limit)) {
	/* return if no need to update the header */
	if (write_all_header == 0) {
	    unlock_fd(pidfd);
	    return (-1);
	}
	toomany = 1;
    }
    else {
	/* update the count */
	if (operation == ACL_JOIN)
	    hdr.count++;
	else if (hdr.count > 0) /* ACL_REMOVE */
	    hdr.count--;
    }

    /* update the header */
    lseek(pidfd, (off_t)0, SEEK_SET);
    if (write_all_header)
	write(pidfd, (void *)&hdr, sizeof(hdr));
    else
	write(pidfd, (void *)&hdr.count, sizeof(hdr.count));

    /* return if no need to update the bitmap */
    if (toomany) {
	unlock_fd(pidfd);
	return (-1);
    }

    /* update the bitmap entry for the process */
    pid = getpid();
    offset = (off_t)(sizeof(hdr) + (pid/CHAR_BIT));
    lseek(pidfd, offset, SEEK_SET);
    if (read(pidfd, (void *)&bits, sizeof(bits)) != sizeof(bits))
	bits = 0;
    if (operation == ACL_JOIN)
	bits |= (1 << (pid%CHAR_BIT));
    else /* ACL_REMOVE */
	bits &= ~(1 << (pid%CHAR_BIT));
    lseek(pidfd, offset, SEEK_SET);
    write(pidfd, (void *)&bits, sizeof(bits));
    unlock_fd(pidfd);
    return (hdr.count);
}

/*************************************************************************/
/* FUNCTION  : open_pidfile                                              */
/* PURPOSE   : Return a file descriptor of an opened PID file.           */
/* ARGUMENTS : Users class.                                              */
/*************************************************************************/

static int open_pidfile(char *class)
{
    int fd;
    mode_t oldmask;
    char pidfile[MAXPATHLEN];

    snprintf(pidfile, sizeof(pidfile), _PATH_PIDNAMES, class);
    oldmask = umask(0);
    fd = open(pidfile, O_RDWR | O_CREAT, 0644);
    (void) umask(oldmask);
    if (fd < 0)
	syslog(LOG_ERR, "cannot open pid file %s: %m", pidfile);
    return (fd);
}

/*************************************************************************/
/* FUNCTION  : acl_countusers                                            */
/* PURPOSE   : Return the number of users in the specified class.        */
/* ARGUMENTS : The name of the class to count.                           */
/*************************************************************************/

int acl_countusers(char *class)
{
    int count = 0, opidfd = pidfd;

    if (Bypass_PID_Files)
	return (0);

    if (pidfd < 0) {
	if ((pidfd = open_pidfile(class)) < 0)
	    return (-1);
    }

    count = limit_op(ACL_COUNT, 0);

    /*
     * acl_countusers may be called from msg_massage before the correct class
     * is known, so close the pid file if we opened it.
     */
    if (opidfd < 0) {
	close(pidfd);
	pidfd = -1;
    }
    return (count);
}

/*************************************************************************/
/* FUNCTION  : acl_join                                                  */
/* PURPOSE   : Add the current process to the list of processes in the   */
/*             specified class.                                          */
/* ARGUMENTS : The name of the class to join, user limit for the class.  */
/* RETURNS   : 0 on success, -1 on failure                               */
/*************************************************************************/

int acl_join(char *class, int limit)
{
    if (Bypass_PID_Files)
	return (0);

    if (pidfd < 0) {
	if ((pidfd = open_pidfile(class)) < 0)
	    return (-1);
    }

    if (limit_op(ACL_JOIN, limit) < 0) {
	/* no need to leave the pid file open as we were not added to it */
	close(pidfd);
	pidfd = -1;
	return (-1);
    }
    /* pidfd left open so can be updated after a chroot */
    return (0);
}

/*************************************************************************/
/* FUNCTION  : acl_remove                                                */
/* PURPOSE   : Remove the current process from the list of processes in  */
/*             our class.                                                */
/* ARGUMENTS : None.                                                     */
/*************************************************************************/

void acl_remove(void)
{
    acl_remhost();

    if (pidfd < 0)
	return;
    (void) limit_op(ACL_REMOVE, 0);
    close(pidfd);
    pidfd = -1;
}

/*************************************************************************/
/* FUNCTION  : pr_mesg                                                   */
/* PURPOSE   : Display a message to the user.                            */
/* ARGUMENTS : Message code, name of file to display.                    */
/*************************************************************************/

void pr_mesg(int msgcode, char *msgfile)
{
    FILE *infile;
    char inbuf[1024], outbuf[1024], *cr;

    if (msgfile && (int) strlen(msgfile) > 0) {
	infile = fopen(msgfile, "r");
	if (infile) {
	    while (fgets(inbuf, sizeof(inbuf), infile) != NULL) {
		if ((cr = strchr(inbuf, '\n')) != NULL)
		    *cr = '\0';
		msg_massage(inbuf, outbuf, sizeof(outbuf));
		lreply(msgcode, "%s", outbuf);
	    }
	    fclose(infile);
	}
    }
}

/*************************************************************************/
/* FUNCTION  : access_init                                               */
/* PURPOSE   : Read and parse the access lists to set things up.         */
/* ARGUMENTS : None.                                                     */
/*************************************************************************/

void access_init(void)
{
    struct aclmember *entry;
    static struct stat sbuf_last;
    struct stat sbuf_cur;

    if (!use_accessfile)
	return;

    if (stat(_path_ftpaccess, &sbuf_cur) != 0) {
	syslog(LOG_ERR, "cannot stat access file %s: %s", _path_ftpaccess,
	       strerror(errno));
	return;
    }
    /* only reload the ftpaccess file if its changed */
    if ((sbuf_last.st_mtime == sbuf_cur.st_mtime) &&
	(sbuf_last.st_ino == sbuf_cur.st_ino) &&
	(sbuf_last.st_dev == sbuf_cur.st_dev))
	return;

    sbuf_last = sbuf_cur;

#if defined(OTHER_PASSWD)
    strlcpy(_path_passwd, "/etc/passwd", MAXPATHLEN);
#  if defined(SHADOW_PASSWORD)
    strlcpy(_path_shadow, "/etc/shadow", MAXPATHLEN);
#  endif /* defined(SHADOW_PASSWORD) */ 
#endif /* defined(OTHER_PASSWD) */ 
#if defined(USE_PAM) && defined(OTHER_PASSWD)
    use_pam = 1;
#endif /* defined(USE_PAM) && defined(OTHER_PASSWD) */ 
    Shutdown[0] = '\0';
    keepalive = 0;

    if (!readacl(_path_ftpaccess))
	return;
    (void) parseacl();

    entry = (struct aclmember *) NULL;
    if (getaclentry("shutdown", &entry) && ARG0 != NULL)
	(void) strlcpy(Shutdown, ARG0, sizeof(Shutdown));
#if defined(OTHER_PASSWD)
    entry = (struct aclmember *) NULL;
    while (getaclentry("passwd", &entry))
	if (ARG0) {
	    strlcpy(_path_passwd, ARG0, MAXPATHLEN);
#  if defined(USE_PAM)
	    use_pam = 0;
#  endif /* defined(USE_PAM) */ 
	}
#  if defined(SHADOW_PASSWORD)
    entry = (struct aclmember *) NULL;
    while (getaclentry("shadow", &entry))
	if (ARG0) {
	    strlcpy(_path_shadow, ARG0, MAXPATHLEN);
#    if defined(USE_PAM)
	    use_pam = 0;
#    endif /* defined(USE_PAM) */ 
	}
#  endif /* defined(SHADOW_PASSWORD) */ 
#endif /* defined(OTHER_PASSWD) */ 
    entry = (struct aclmember *) NULL;
    if (getaclentry("keepalive", &entry) && ARG0 != NULL)
	if (!strcasecmp(ARG0, "yes"))
	    keepalive = 1;
}

/*************************************************************************/
/* FUNCTION  : access_ok                                                 */
/* PURPOSE   : Check to see if this access is permitted.                 */
/* ARGUMENTS : Reply code to use.                                        */
/*************************************************************************/

int access_ok(int msgcode)
{
    char class[1024], msgfile[MAXPATHLEN];
    int limit;

    if (!use_accessfile)
	return (1);

    if (aclbuf == NULL) {
	syslog(LOG_NOTICE,
	       "ACCESS DENIED (error reading access file) TO %s",
	       remoteident);
	return (0);
    }
    if (acl_deny(msgfile, sizeof(msgfile))) {
#if !defined(HELP_CRACKERS)
	memcpy(DelayedMessageFile, msgfile, sizeof(msgfile));
#else /* !(!defined(HELP_CRACKERS)) */ 
	pr_mesg(msgcode, msgfile);
#endif /* !(!defined(HELP_CRACKERS)) */ 
	syslog(LOG_NOTICE, "ACCESS DENIED (deny command) TO %s",
	       remoteident);
	return (0);
    }
    /* if user is not in any class, deny access */
    if (!acl_getclass(class, sizeof(class))) {
	syslog(LOG_NOTICE, "ACCESS DENIED (not in any class) TO %s",
	       remoteident);
	return (0);
    }

    limit = acl_getlimit(class, msgfile, sizeof(msgfile));
    if (acl_join(class, limit) < 0) {
#if defined(LOG_TOOMANY)
	syslog(LOG_NOTICE, "ACCESS DENIED (user limit %d; class %s) TO %s",
	       limit, class, remoteident);
#endif /* !(defined(LOG_TOOMANY)) */
#if !defined(HELP_CRACKERS)
	memcpy(DelayedMessageFile, msgfile, sizeof(msgfile));
#else /* !(!defined(HELP_CRACKERS)) */ 
	pr_mesg(msgcode, msgfile);
#endif /* !(!defined(HELP_CRACKERS)) */ 
	return (-1);
    }

    limit = acl_gethostlimit(class, msgfile, sizeof(msgfile));
    if (acl_addhost(class, limit) < 0) {
#if defined(LOG_TOOMANY)
	syslog(LOG_NOTICE, "ACCESS DENIED (host limit %d; class %s) TO %s",
	       limit, class, remoteident);
#endif /* defined(LOG_TOOMANY) */ 
#if !defined(HELP_CRACKERS)
	memcpy(DelayedMessageFile, msgfile, sizeof (msgfile));
#else /* !(!defined(HELP_CRACKERS)) */ 
	pr_mesg(msgcode, msgfile);
#endif /* !(!defined(HELP_CRACKERS)) */ 
	acl_remove();
	return (-1);
    }

    acl_getnice(class);
    acl_getdefumask(class);
    acl_tcpwindow(class);
#if defined(TRANSFER_COUNT)
#  if defined(TRANSFER_LIMIT)
    acl_filelimit(class);
    acl_datalimit(class);
#    if defined(RATIO)
    acl_downloadrate(class);
#    endif /* defined(RATIO) */ 
#  endif /* defined(TRANSFER_LIMIT) */ 
#endif /* defined(TRANSFER_COUNT) */ 
    acl_bufsize();
    get_xferlog_format();
    return (1);
}

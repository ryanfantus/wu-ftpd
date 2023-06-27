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
   
  $Id: realpath.c,v 1.9 2011/10/20 22:58:11 wmaton Exp $  
   
****************************************************************************/
/* Originally taken from FreeBSD 3.0's libc; adapted to handle chroot
 * directories in BeroFTPD by Bernhard Rosenkraenzer
 * <bero@beroftpd.unix.eu.org>
 *
 * Added super-user permissions so we can determine the real pathname even
 * if the user cannot access the file. <lundberg+wuftpd@vr.net>
 */
#include "config.h"

#include <sys/param.h>
#include <sys/stat.h>

#include <errno.h>
#if defined(HAVE_FCNTL_H)
#  include <fcntl.h>
#endif /* defined(HAVE_FCNTL_H) */ 
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "proto.h"

#if !defined(MAXSYMLINKS)		/* Workaround for Linux libc 4.x/5.x */
#  define MAXSYMLINKS 5
#endif /* !defined(MAXSYMLINKS)		-  Workaround for Linux libc 4.x-5.x */ 

#if !defined(HAVE_LSTAT)
#  define lstat stat
#endif /* !defined(HAVE_LSTAT) */ 

char *wu_realpath(const char *path, char resolved_path[MAXPATHLEN], char *chroot_path)
{
    char *ptr;
    char q[MAXPATHLEN];

    fb_realpath(path, q);

    if (chroot_path == NULL)
	strlcpy(resolved_path, q, MAXPATHLEN);
    else {
	strlcpy(resolved_path, chroot_path, MAXPATHLEN);
	if (q[0] != '/') {
	    if (strlen(resolved_path) + strlen(q) < MAXPATHLEN)
		strlcat(resolved_path, q, MAXPATHLEN);
	    else		/* Avoid buffer overruns... */
		return NULL;
	}
	else if (q[1] != '\0') {
	    for (ptr = q; *ptr != '\0'; ptr++);
	    if (ptr == resolved_path || *--ptr != '/') {
		if (strlen(resolved_path) + strlen(q) < MAXPATHLEN)
		    strlcat(resolved_path, q, MAXPATHLEN);
		else		/* Avoid buffer overruns... */
		    return NULL;
	    }
	    else {
		if (strlen(resolved_path) + strlen(q) - 1 < MAXPATHLEN)
		    strlcat(resolved_path, &q[1], MAXPATHLEN);
		else		/* Avoid buffer overruns... */
		    return NULL;
	    }
	}
    }
    return resolved_path;
}

/*
 * char *fb_realpath(const char *path, char resolved_path[MAXPATHLEN]);
 *
 * Find the real name of path, by removing all ".", ".." and symlink
 * components.  Returns (resolved) on success, or (NULL) on failure,
 * in which case the path which caused trouble is left in (resolved).
 */
char *fb_realpath(const char *path, char *resolved)
{
    struct stat sb;
    int fd, n, rootd, serrno;
    char *p, *q, wbuf[MAXPATHLEN];
    int symlinks = 0;
    int resultcode;
#if defined(HAS_NO_FCHDIR)
/* AIX Has no fchdir() so we hope the getcwd() call doesn't overrun the buffer! */
    char cwd[MAXPATHLEN + 1];
    char *pcwd;
#endif /* defined(HAS_NO_FCHDIR) */ 

    /* Save the starting point. */
    errno = 0;
#if defined(HAS_NO_FCHDIR)
#  if defined(HAVE_GETCWD)
    pcwd = getcwd(cwd, sizeof(cwd));
#  else /* !(defined(HAVE_GETCWD)) */ 
    pcwd = getwd(cwd);
#  endif /* !(defined(HAVE_GETCWD)) */ 
#else /* !(defined(HAS_NO_FCHDIR)) */ 
    fd = open(".", O_RDONLY);
#endif /* !(defined(HAS_NO_FCHDIR)) */ 
    if (EACCES == errno) {
	uid_t userid = geteuid();
	delay_signaling();	/* we can't allow any signals while euid==0: kinch */
	seteuid(0);
#if defined(HAS_NO_FCHDIR)
#  if defined(HAVE_GETCWD)
	pcwd = getcwd(cwd, sizeof(cwd));
#  else /* !(defined(HAVE_GETCWD)) */ 
	pcwd = getwd(cwd);
#  endif /* !(defined(HAVE_GETCWD)) */ 
#else /* !(defined(HAS_NO_FCHDIR)) */ 
	fd = open(".", O_RDONLY);
#endif /* !(defined(HAS_NO_FCHDIR)) */ 
	seteuid(userid);
	enable_signaling();	/* we can allow signals once again: kinch */
    }
#if defined(HAS_NO_FCHDIR)
    if (pcwd == NULL)
#else /* !(defined(HAS_NO_FCHDIR)) */ 
    if (fd < 0)
#endif /* !(defined(HAS_NO_FCHDIR)) */ 
    {
	(void) strlcpy(resolved, ".", MAXPATHLEN);
	return (NULL);
    }

    /*
     * Find the dirname and basename from the path to be resolved.
     * Change directory to the dirname component.
     * lstat the basename part.
     *     if it is a symlink, read in the value and loop.
     *     if it is a directory, then change to that directory.
     * get the current directory name and append the basename.
     */
    (void) strlcpy(resolved, path, MAXPATHLEN);
    
  loop:
    q = strrchr(resolved, '/');
    if (q != NULL) {
	p = q + 1;
	if (q == resolved)
	    q = "/";
	else {
	    do {
		--q;
	    } while (q > resolved && *q == '/');
	    q[1] = '\0';
	    q = resolved;
	}
	errno = 0;
	resultcode = chdir(q);
	if (EACCES == errno) {
	    uid_t userid = geteuid();
	    delay_signaling();	/* we can't allow any signals while euid==0: kinch */
	    seteuid(0);
	    errno = 0;
	    resultcode = chdir(q);
	    seteuid(userid);
	    enable_signaling();	/* we can allow signals once again: kinch */
	}
	if (resultcode < 0)
	    goto err1;
    }
    else
	p = resolved;

    /* Deal with the last component. */
    if (*p != '\0') {
	errno = 0;
	resultcode = lstat(p, &sb);
	if (EACCES == errno) {
	    uid_t userid = geteuid();
	    delay_signaling();	/* we can't allow any signals while euid==0: kinch */
	    seteuid(0);
	    errno = 0;
	    resultcode = lstat(p, &sb);
	    seteuid(userid);
	    enable_signaling();	/* we can allow signals once again: kinch */
	}
	if (resultcode == 0) {
#if defined(HAVE_LSTAT)
	    if (S_ISLNK(sb.st_mode)) {
		if (++symlinks > MAXSYMLINKS) {
		    errno = ELOOP;
		    goto err1;
		}
		errno = 0;
		{
		    size_t len = strlen(p)+1;
		    char *tmp = calloc(len, sizeof(char));
		    if (tmp == 0) {
			serrno = errno;
			goto err1;
		    }
		    strlcpy(tmp, p, len);
		    p = tmp;
		}
		n = readlink(p, resolved, MAXPATHLEN);
		if (EACCES == errno) {
		    uid_t userid = geteuid();
		    delay_signaling();	/* we can't allow any signals while euid==0: kinch */
		    seteuid(0);
		    errno = 0;
		    n = readlink(p, resolved, MAXPATHLEN);
		    seteuid(userid);
		    enable_signaling();		/* we can allow signals once again: kinch */
		}
		if (n < 0) {
		    free(p);
		    goto err1;
		}
		free(p);
		/* n should be less than MAXPATHLEN, but check to be safe */
		if (n >= MAXPATHLEN)
		    n = MAXPATHLEN - 1;
		resolved[n] = '\0';
		goto loop;
	    }
#endif /* defined(HAVE_LSTAT) */ 
	    if (S_ISDIR(sb.st_mode)) {
		errno = 0;
		resultcode = chdir(p);
		if (EACCES == errno) {
		    uid_t userid = geteuid();
		    delay_signaling();	/* we can't allow any signals while euid==0: kinch */
		    seteuid(0);
		    errno = 0;
		    resultcode = chdir(p);
		    seteuid(userid);
		    enable_signaling();		/* we can allow signals once again: kinch */
		}
		if (resultcode < 0)
		    goto err1;
		p = "";
	    }
	}
    }

    /*
     * Save the last component name and get the full pathname of
     * the current directory.
     */
    (void) strlcpy(wbuf, p, sizeof(wbuf));
    errno = 0;
#if defined(HAVE_GETCWD)
    resultcode = getcwd(resolved, MAXPATHLEN) == NULL ? 0 : 1;
#else /* !(defined(HAVE_GETCWD)) */ 
    resultcode = getwd(resolved) == NULL ? 0 : 1;
    if (resolved[MAXPATHLEN - 1] != '\0') {
	resultcode = 0;
	errno = ERANGE;
    }
#endif /* !(defined(HAVE_GETCWD)) */ 
    if (EACCES == errno) {
	uid_t userid = geteuid();
	delay_signaling();	/* we can't allow any signals while euid==0: kinch */
	seteuid(0);
	errno = 0;
#if defined(HAVE_GETCWD)
	resultcode = getcwd(resolved, MAXPATHLEN) == NULL ? 0 : 1;
#else /* !(defined(HAVE_GETCWD)) */ 
	resultcode = getwd(resolved) == NULL ? 0 : 1;
	if (resolved[MAXPATHLEN - 1] != '\0') {
	    resultcode = 0;
	    errno = ERANGE;
	}
#endif /* !(defined(HAVE_GETCWD)) */ 
	seteuid(userid);
	enable_signaling();	/* we can allow signals once again: kinch */
    }
    if (resultcode == 0)
	goto err1;

    /*
     * Join the two strings together, ensuring that the right thing
     * happens if the last component is empty, or the dirname is root.
     */
    if (resolved[0] == '/' && resolved[1] == '\0')
	rootd = 1;
    else
	rootd = 0;

    if (*wbuf) {
	if (strlen(resolved) + strlen(wbuf) + !rootd + 1 > MAXPATHLEN) {
	    errno = ENAMETOOLONG;
	    goto err1;
	}
	if (rootd == 0)
	    (void) strlcat(resolved, "/", MAXPATHLEN);
	(void) strlcat(resolved, wbuf, MAXPATHLEN);
    }

    /* Go back to where we came from. */
    errno = 0;
#if defined(HAS_NO_FCHDIR)
    resultcode = chdir(cwd);
#else /* !(defined(HAS_NO_FCHDIR)) */ 
    resultcode = fchdir(fd);
#endif /* !(defined(HAS_NO_FCHDIR)) */ 
    if (EACCES == errno) {
	uid_t userid = geteuid();
	delay_signaling();	/* we can't allow any signals while euid==0: kinch */
	seteuid(0);
	errno = 0;
#if defined(HAS_NO_FCHDIR)
	resultcode = chdir(cwd);
#else /* !(defined(HAS_NO_FCHDIR)) */ 
	resultcode = fchdir(fd);
#endif /* !(defined(HAS_NO_FCHDIR)) */ 
	seteuid(userid);
	enable_signaling();	/* we can allow signals once again: kinch */
    }
    if (resultcode < 0) {
	serrno = errno;
	goto err2;
    }

#if !defined(HAS_NO_FCHDIR)
    /* It's okay if the close fails, what's an fd more or less? */
    (void) close(fd);
#endif /* !defined(HAS_NO_FCHDIR) */ 
    return (resolved);

  err1:serrno = errno;
#if defined(HAS_NO_FCHDIR)
    (void) chdir(cwd);
#else /* !(defined(HAS_NO_FCHDIR)) */ 
    (void) fchdir(fd);
#endif /* !(defined(HAS_NO_FCHDIR)) */ 
    if (EACCES == errno) {
	uid_t userid = geteuid();
	delay_signaling();	/* we can't allow any signals while euid==0: kinch */
	seteuid(0);
#if defined(HAS_NO_FCHDIR)
	(void) chdir(cwd);
#else /* !(defined(HAS_NO_FCHDIR)) */ 
	(void) fchdir(fd);
#endif /* !(defined(HAS_NO_FCHDIR)) */ 
	seteuid(userid);
	enable_signaling();	/* we can allow signals once again: kinch */
    }
#if defined(HAS_NO_FCHDIR)
  err2:errno = serrno;
#else /* !(defined(HAS_NO_FCHDIR)) */ 
  err2:(void) close(fd);
    errno = serrno;
#endif /* !(defined(HAS_NO_FCHDIR)) */ 
    return (NULL);
}

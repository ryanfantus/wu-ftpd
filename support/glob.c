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
 
  $Id: glob.c,v 1.9 2011/10/20 22:58:13 wmaton Exp $
 
****************************************************************************/
/* AIX requires this to be the first thing in the file.  */

#include "../config.h"
#include "../src/config.h"

#if defined _AIX && !defined __GNUC__
#  pragma alloca
#endif /* defined _AIX && !defined __GNUC__ */ 

#if defined(HAVE_CONFIG_H)
#  include <config.h>
#endif /* defined(HAVE_CONFIG_H) */ 

/* Enable GNU extensions in glob.h.  */
#if !defined(_GNU_SOURCE)
#  define _GNU_SOURCE	1
#endif /* !defined(_GNU_SOURCE) */ 

#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>

/* Outcomment the following line for production quality code.  */
/* #define NDEBUG 1 */
#include <assert.h>

#include <stdio.h>		/* Needed on stupid SunOS for assert.  */
#include <unistd.h>		/* Needed on stupid SunOS for getlogin. */

/* Comment out all this code if we are using the GNU C Library, and are not
   actually compiling the library itself.  This code is part of the GNU C
   Library, but also included in many other GNU distributions.  Compiling
   and linking in this code is a waste when using the GNU C library
   (especially if it is a shared library).  Rather than having every GNU
   program understand `configure --with-gnu-libc' and omit the object files,
   it is simpler to just do this in the source for each such file.  */

#define GLOB_INTERFACE_VERSION 1
#if !defined _LIBC && defined __GNU_LIBRARY__ && __GNU_LIBRARY__ > 1
#  include <gnu-versions.h>
#  if _GNU_GLOB_INTERFACE_VERSION == GLOB_INTERFACE_VERSION
#    define ELIDE_CODE
#  endif /* _GNU_GLOB_INTERFACE_VERSION == GLOB_INTERFACE_VERSION */ 
#endif /* !defined _LIBC && defined __GNU_LIBRARY__ && __GNU_LIBRARY__ > 1 */ 

#if !defined(ELIDE_CODE)

#  if defined STDC_HEADERS || defined __GNU_LIBRARY__
#    include <stddef.h>
#  endif /* defined STDC_HEADERS || defined __GNU_LIBRARY__ */ 

#  if defined HAVE_UNISTD_H || defined _LIBC
#    include <unistd.h>
#    if !defined(POSIX)
#      if defined(_POSIX_VERSION)
#        define POSIX
#      endif /* defined(_POSIX_VERSION) */ 
#    endif /* !defined(POSIX) */ 
#  endif /* defined HAVE_UNISTD_H || defined _LIBC */ 

#  if !defined _AMIGA && !defined VMS && !defined WINDOWS32
#    include <pwd.h>
#  endif /* !defined _AMIGA && !defined VMS && !defined WINDOWS32 */ 

#  if !defined __GNU_LIBRARY__ && !defined STDC_HEADERS
extern int errno;
#  endif /* !defined __GNU_LIBRARY__ && !defined STDC_HEADERS */ 
#  if !defined(__set_errno)
#    define __set_errno(val) errno = (val)
#  endif /* !defined(__set_errno) */ 

#  if !defined(NULL)
#    define NULL	0
#  endif /* !defined(NULL) */ 


#  if defined HAVE_DIRENT_H || defined __GNU_LIBRARY__
#    include <dirent.h>
#    define NAMLEN(dirent) strlen((dirent)->d_name)
#  else /* !(defined HAVE_DIRENT_H || defined __GNU_LIBRARY__) */ 
#    define dirent direct
#    define NAMLEN(dirent) (dirent)->d_namlen
#    if defined(HAVE_SYS_NDIR_H)
#      include <sys/ndir.h>
#    endif /* defined(HAVE_SYS_NDIR_H) */ 
#    if defined(HAVE_SYS_DIR_H)
#      include <sys/dir.h>
#    endif /* defined(HAVE_SYS_DIR_H) */ 
#    if defined(HAVE_NDIR_H)
#      include <ndir.h>
#    endif /* defined(HAVE_NDIR_H) */ 
#    if defined(HAVE_VMSDIR_H)
#      include "vmsdir.h"
#    endif /* defined(HAVE_VMSDIR_H) */ 
#  endif /* !(defined HAVE_DIRENT_H || defined __GNU_LIBRARY__) */ 


/* In GNU systems, <dirent.h> defines this macro for us.  */
#  if defined(_D_NAMLEN)
#    undef NAMLEN
#    define NAMLEN(d) _D_NAMLEN(d)
#  endif /* defined(_D_NAMLEN) */ 

/* When used in the GNU libc the symbol _DIRENT_HAVE_D_TYPE is available
   if the `d_type' member for `struct dirent' is available.  */
#  if defined(_DIRENT_HAVE_D_TYPE)
#    define HAVE_D_TYPE	1
#  endif /* defined(_DIRENT_HAVE_D_TYPE) */ 


#  if (defined POSIX || defined WINDOWS32) && !defined __GNU_LIBRARY__
/* Posix does not require that the d_ino field be present, and some
   systems do not provide it. */
#    define REAL_DIR_ENTRY(dp) 1
#  else /* !((defined POSIX || defined WINDOWS32) && !defined __GNU_LIBRARY__) */ 
#    define REAL_DIR_ENTRY(dp) (dp->d_ino != 0)
#  endif /* !((defined POSIX || defined WINDOWS32) && !defined __GNU_LIBRARY__) */ 

#  if sparc && !__svr4__
#    include <string.h>
#    include <dirent.h>
#  endif /* sparc && !__svr4__ */ 

#  if defined STDC_HEADERS || defined __GNU_LIBRARY__
#    include <stdlib.h>
#    include <string.h>
#    define ANSI_STRING
#  else /* !(defined STDC_HEADERS || defined __GNU_LIBRARY__) */ 

extern char *getenv();

#    if defined(HAVE_STRING_H)
#      include <string.h>
#      define ANSI_STRING
#    else /* !(defined(HAVE_STRING_H)) */ 
#      include <strings.h>
#    endif /* !(defined(HAVE_STRING_H)) */ 
#    if defined(HAVE_MEMORY_H)
#      include <memory.h>
#    endif /* defined(HAVE_MEMORY_H) */ 

#  endif /* !(defined STDC_HEADERS || defined __GNU_LIBRARY__) */ 

#  if !defined(HAVE_MEMCPY)
#    define memcpy(d, s, n)	bcopy ((s), (d), (n))
#  endif /* !defined(HAVE_MEMCPY) */ 
#  if !defined(ANSI_STRING)

#    if !defined(bzero)
extern void bzero();
#    endif /* !defined(bzero) */ 
#    if !defined(bcopy)
extern void bcopy();
#    endif /* !defined(bcopy) */ 

#    define strrchr	rindex
/* memset is only used for zero here, but let's be paranoid.  */
#    define memset(s, better_be_zero, n) \
  (((better_be_zero) == 0 ? (bzero((s), (n)), 0) : (abort(), 0)))
#  endif /* !defined(ANSI_STRING) */ 

#  if !defined HAVE_STRCOLL && !defined _LIBC
#    define strcoll	strcmp
#  endif /* !defined HAVE_STRCOLL && !defined _LIBC */ 

#  if !defined HAVE_MEMPCPY && __GLIBC__ - 0 == 2 && __GLIBC_MINOR__ >= 1
#    define HAVE_MEMPCPY	1
#    define mempcpy(Dest, Src, Len) __mempcpy (Dest, Src, Len)
#  endif /* !defined HAVE_MEMPCPY && __GLIBC__ - 0 == 2 && __GLIBC_MINOR__ >= 1 */ 


#  if !defined(__GNU_LIBRARY__)
#    if defined(__GNUC__)
__inline
#    endif /* defined(__GNUC__) */ 
#    if !defined(__SASC)
#      if defined(WINDOWS32)
static void *
#      else /* !(defined(WINDOWS32)) */ 
static char *
#      endif /* !(defined(WINDOWS32)) */ 
     my_realloc(p, n)
     char *p;
     unsigned int n;
{
    /* These casts are the for sake of the broken Ultrix compiler,
       which warns of illegal pointer combinations otherwise.  */
    if (p == NULL)
	return (char *) malloc(n);
    return (char *) realloc(p, n);
}

#      define realloc	my_realloc
#    endif /* !defined(__SASC) */ 
#  endif /* !defined(__GNU_LIBRARY__) */ 


#  if !defined __alloca && !defined __GNU_LIBRARY__

#    if defined(__GNUC__)
#      undef alloca
#      define alloca(n)	__builtin_alloca (n)
#    else /* !(defined(__GNUC__)) */ 
#      if defined(HAVE_ALLOCA_H)
#        include <alloca.h>
#      else /* !(defined(HAVE_ALLOCA_H)) */ 
#        if !defined(_AIX)
#          if defined(WINDOWS32)
#            include <malloc.h>
#          else /* !(defined(WINDOWS32)) */ 
extern char *alloca();
#          endif /* !(defined(WINDOWS32)) */ 
#        endif /* !defined(_AIX) */ 
#      endif /* !(defined(HAVE_ALLOCA_H)) */ 
#    endif /* !(defined(__GNUC__)) */ 

#    define __alloca	alloca

#  endif /* !defined __alloca && !defined __GNU_LIBRARY__ */ 

#  if !defined(__GNU_LIBRARY__)
#    define __stat stat
#    if defined(STAT_MACROS_BROKEN)
#      undef S_ISDIR
#    endif /* defined(STAT_MACROS_BROKEN) */ 
#    if !defined(S_ISDIR)
#      define S_ISDIR(mode) (((mode) & S_IFMT) == S_IFDIR)
#    endif /* !defined(S_ISDIR) */ 
#  endif /* !defined(__GNU_LIBRARY__) */ 

#  if !(defined STDC_HEADERS || defined __GNU_LIBRARY__)
#    undef size_t
#    define size_t	unsigned int
#  endif /* !(defined STDC_HEADERS || defined __GNU_LIBRARY__) */ 

/* Some system header files erroneously define these.
   We want our own definitions from <fnmatch.h> to take precedence.  */
#  undef FNM_CASEFOLD
#  undef FNM_NOESCAPE
#  undef FNM_PERIOD
#  include "../src/wu_fnmatch.h"

/* Some system header files erroneously define these.
   We want our own definitions from <glob.h> to take precedence.  */
#  undef GLOB_ERR
#  undef GLOB_MARK
#  undef GLOB_NOSORT
#  undef GLOB_DOOFFS
#  undef GLOB_NOCHECK
#  undef GLOB_APPEND
#  undef GLOB_NOESCAPE
#  undef GLOB_PERIOD
#  include "wuftpd_glob.h"

static
#  if __GNUC__ - 0 >= 2
       inline
#  endif /* __GNUC__ - 0 >= 2 */ 
const char *next_brace_sub __P((const char *begin));
static int glob_in_dir __P((const char *pattern, const char *directory,
			    int flags,
			    int         (*errfunc) __P((const char *, int)),
			    glob_t * pglob));
static int prefix_array __P((const char *prefix, char **array, size_t n));
static int collated_compare __P((const __ptr_t, const __ptr_t));


/* Find the end of the sub-pattern in a brace expression.  We define
   this as an inline function if the compiler permits.  */
static
#  if __GNUC__ - 0 >= 2
       inline
#  endif /* __GNUC__ - 0 >= 2 */ 
const char *
     next_brace_sub(begin)
     const char *begin;
{
    unsigned int depth = 0;
    const char *cp = begin;

    while (1) {
	if (depth == 0) {
	    if (*cp != ',' && *cp != '}' && *cp != '\0') {
		if (*cp == '{')
		    ++depth;
		++cp;
		continue;
	    }
	}
	else {
	    while (*cp != '\0' && (*cp != '}' || depth > 0)) {
		if (*cp == '}')
		    --depth;
		++cp;
	    }
	    if (*cp == '\0')
		/* An incorrectly terminated brace expression.  */
		return NULL;

	    continue;
	}
	break;
    }

    return cp;
}

/* Do glob searching for PATTERN, placing results in PGLOB.
   The bits defined above may be set in FLAGS.
   If a directory cannot be opened or read and ERRFUNC is not nil,
   it is called with the pathname that caused the error, and the
   `errno' value from the failing call; if it returns non-zero
   `glob' returns GLOB_ABORTED; if it returns zero, the error is ignored.
   If memory cannot be allocated for PGLOB, GLOB_NOSPACE is returned.
   Otherwise, `glob' returns zero.  */
int glob(pattern, flags, errfunc, pglob)
     const char *pattern;
     int flags;
     int (*errfunc) __P((const char *, int));
     glob_t *pglob;
{
    const char *filename;
    char *dirname;
    size_t dirlen;
    int status;
    int oldcount;

    if (pattern == NULL || pglob == NULL || (flags & ~__GLOB_FLAGS) != 0) {
	__set_errno(EINVAL);
	return -1;
    }

    if (flags & GLOB_BRACE) {
	const char *begin = strchr(pattern, '{');
	if (begin != NULL) {
	    /* Allocate working buffer large enough for our work.  Note that
	       we have at least an opening and closing brace.  */
	    int firstc;
	    char *alt_start;
	    const char *p;
	    const char *next;
	    const char *rest;
	    size_t rest_len;
#  if defined(__GNUC__)
	    char onealt[strlen(pattern) - 1];
#  else /* !(defined(__GNUC__)) */ 
	    char *onealt = (char *) malloc(strlen(pattern) - 1);
	    if (onealt == NULL) {
		if (!(flags & GLOB_APPEND))
		    globfree(pglob);
		return GLOB_NOSPACE;
	    }
#  endif /* !(defined(__GNUC__)) */ 

	    /* We know the prefix for all sub-patterns.  */
#  if defined(HAVE_MEMPCPY)
	    alt_start = mempcpy(onealt, pattern, begin - pattern);
#  else /* !(defined(HAVE_MEMPCPY)) */ 
	    memcpy(onealt, pattern, begin - pattern);
	    alt_start = &onealt[begin - pattern];
#  endif /* !(defined(HAVE_MEMPCPY)) */ 

	    /* Find the first sub-pattern and at the same time find the
	       rest after the closing brace.  */
	    next = next_brace_sub(begin + 1);
	    if (next == NULL) {
		/* It is an illegal expression.  */
#  if !defined(__GNUC__)
		free(onealt);
#  endif /* !defined(__GNUC__) */ 
		return glob(pattern, flags & ~GLOB_BRACE, errfunc, pglob);
	    }

	    /* Now find the end of the whole brace expression.  */
	    rest = next;
	    while (*rest != '}') {
		rest = next_brace_sub(rest + 1);
		if (rest == NULL) {
		    /* It is an illegal expression.  */
#  if !defined(__GNUC__)
		    free(onealt);
#  endif /* !defined(__GNUC__) */ 
		    return glob(pattern, flags & ~GLOB_BRACE, errfunc, pglob);
		}
	    }
	    /* Please note that we now can be sure the brace expression
	       is well-formed.  */
	    rest_len = strlen(++rest) + 1;

	    /* We have a brace expression.  BEGIN points to the opening {,
	       NEXT points past the terminator of the first element, and END
	       points past the final }.  We will accumulate result names from
	       recursive runs for each brace alternative in the buffer using
	       GLOB_APPEND.  */

	    if (!(flags & GLOB_APPEND)) {
		/* This call is to set a new vector, so clear out the
		   vector so we can append to it.  */
		pglob->gl_pathc = 0;
		pglob->gl_pathv = NULL;
	    }
	    firstc = pglob->gl_pathc;

	    p = begin + 1;
	    while (1) {
		int result;

		/* Construct the new glob expression.  */
#  if defined(HAVE_MEMPCPY)
		mempcpy(mempcpy(alt_start, p, next - p), rest, rest_len);
#  else /* !(defined(HAVE_MEMPCPY)) */ 
		memcpy(alt_start, p, next - p);
		memcpy(&alt_start[next - p], rest, rest_len);
#  endif /* !(defined(HAVE_MEMPCPY)) */ 

		result = glob(onealt,
			      ((flags & ~(GLOB_NOCHECK | GLOB_NOMAGIC))
			       | GLOB_APPEND), errfunc, pglob);

		/* If we got an error, return it.  */
		if (result && result != GLOB_NOMATCH) {
#  if !defined(__GNUC__)
		    free(onealt);
#  endif /* !defined(__GNUC__) */ 
		    if (!(flags & GLOB_APPEND))
			globfree(pglob);
		    return result;
		}

		if (*next == '}')
		    /* We saw the last entry.  */
		    break;

		p = next + 1;
		next = next_brace_sub(p);
		assert(next != NULL);
	    }

#  if !defined(__GNUC__)
	    free(onealt);
#  endif /* !defined(__GNUC__) */ 

	    if (pglob->gl_pathc != firstc)
		/* We found some entries.  */
		return 0;
	    else if (!(flags & (GLOB_NOCHECK | GLOB_NOMAGIC)))
		return GLOB_NOMATCH;
	}
    }

    /* Find the filename.  */
    filename = strrchr(pattern, '/');
    if (filename == NULL) {
	filename = pattern;
#  if defined(_AMIGA)
	dirname = (char *) "";
#  else /* !(defined(_AMIGA)) */ 
	dirname = (char *) ".";
#  endif /* !(defined(_AMIGA)) */ 
	dirlen = 0;
    }
    else if (filename == pattern) {
	/* "/pattern".  */
	dirname = (char *) "/";
	dirlen = 1;
	++filename;
    }
    else {
	dirlen = filename - pattern;
	dirname = (char *) __alloca(dirlen + 1);
#  if defined(HAVE_MEMPCPY)
	*((char *) mempcpy(dirname, pattern, dirlen)) = '\0';
#  else /* !(defined(HAVE_MEMPCPY)) */ 
	memcpy(dirname, pattern, dirlen);
	dirname[dirlen] = '\0';
#  endif /* !(defined(HAVE_MEMPCPY)) */ 
	++filename;
    }

    if (filename[0] == '\0' && dirlen > 1)
	/* "pattern/".  Expand "pattern", appending slashes.  */
    {
	int val = glob(dirname, flags | GLOB_MARK, errfunc, pglob);
	if (val == 0)
	    pglob->gl_flags = (pglob->gl_flags & ~GLOB_MARK) | (flags & GLOB_MARK);
	return val;
    }

    if (!(flags & GLOB_APPEND)) {
	pglob->gl_pathc = 0;
	pglob->gl_pathv = NULL;
    }

    oldcount = pglob->gl_pathc;

#  if !defined(VMS)
    if ((flags & GLOB_TILDE) && dirname[0] == '~') {
	if (dirname[1] == '\0' || dirname[1] == '/') {
	    /* Look up home directory.  */
	    char *home_dir = getenv("HOME");
#    if defined(_AMIGA)
	    if (home_dir == NULL || home_dir[0] == '\0')
		home_dir = "SYS:";
#    else /* !(defined(_AMIGA)) */ 
#      if defined(WINDOWS32)
	    if (home_dir == NULL || home_dir[0] == '\0')
		home_dir = "c:/users/default";	/* poor default */
#      else /* !(defined(WINDOWS32)) */ 
	    if (home_dir == NULL || home_dir[0] == '\0') {
		int success;
#        if defined HAVE_GETLOGIN_R || defined _LIBC
		extern int getlogin_r __P((char *, size_t));
		size_t buflen = sysconf(_SC_LOGIN_NAME_MAX) + 1;
		char *name;

		if (buflen == 0)
		    /* `sysconf' does not support _SC_LOGIN_NAME_MAX.  Try
		       a moderate value.  */
		    buflen = 16;
		name = (char *) __alloca(buflen);

		success = getlogin_r(name, buflen) >= 0;
#        else /* !(defined HAVE_GETLOGIN_R || defined _LIBC) */ 
/*            extern char *getlogin __P (); */
		char *name;

		success = (name = getlogin()) != NULL;
#        endif /* !(defined HAVE_GETLOGIN_R || defined _LIBC) */ 
		if (success) {
#        if defined HAVE_GETPWNAM_R || defined _LIBC
		    size_t pwbuflen = sysconf(_SC_GETPW_R_SIZE_MAX);
		    char *pwtmpbuf;
		    struct passwd pwbuf, *p;

		    pwtmpbuf = (char *) __alloca(pwbuflen);

		    success = (__getpwnam_r(name, &pwbuf, pwtmpbuf,
					    pwbuflen, &p) >= 0);
#        else /* !(defined HAVE_GETPWNAM_R || defined _LIBC) */ 
		    struct passwd *p = getpwnam(name);
		    success = p != NULL;
#        endif /* !(defined HAVE_GETPWNAM_R || defined _LIBC) */ 
		    if (success)
			home_dir = p->pw_dir;
		}
	    }
	    if (home_dir == NULL || home_dir[0] == '\0')
		home_dir = (char *) "~";	/* No luck.  */
#      endif /* !(defined(WINDOWS32)) */ 
#    endif /* !(defined(_AMIGA)) */ 
	    /* Now construct the full directory.  */
	    if (dirname[1] == '\0')
		dirname = home_dir;
	    else {
		char *newp;
		size_t home_len = strlen(home_dir);
		newp = (char *) __alloca(home_len + dirlen);
#    if defined(HAVE_MEMPCPY)
		mempcpy(mempcpy(newp, home_dir, home_len),
			&dirname[1], dirlen);
#    else /* !(defined(HAVE_MEMPCPY)) */ 
		memcpy(newp, home_dir, home_len);
		memcpy(&newp[home_len], &dirname[1], dirlen);
#    endif /* !(defined(HAVE_MEMPCPY)) */ 
		dirname = newp;
	    }
	}
#    if !defined _AMIGA && !defined WINDOWS32
	else {
	    char *end_name = strchr(dirname, '/');
	    char *user_name;
	    char *home_dir;

	    if (end_name == NULL)
		user_name = dirname + 1;
	    else {
		user_name = (char *) __alloca(end_name - dirname);
#      if defined(HAVE_MEMPCPY)
		*((char *) mempcpy(user_name, dirname + 1, end_name - dirname))
		    = '\0';
#      else /* !(defined(HAVE_MEMPCPY)) */ 
		memcpy(user_name, dirname + 1, end_name - dirname);
		user_name[end_name - dirname - 1] = '\0';
#      endif /* !(defined(HAVE_MEMPCPY)) */ 
	    }

	    /* Look up specific user's home directory.  */
	    {
#      if defined HAVE_GETPWNAM_R || defined _LIBC
		size_t buflen = sysconf(_SC_GETPW_R_SIZE_MAX);
		char *pwtmpbuf = (char *) __alloca(buflen);
		struct passwd pwbuf, *p;
		if (__getpwnam_r(user_name, &pwbuf, pwtmpbuf, buflen, &p) >= 0)
		    home_dir = p->pw_dir;
		else
		    home_dir = NULL;
#      else /* !(defined HAVE_GETPWNAM_R || defined _LIBC) */ 
		struct passwd *p = getpwnam(user_name);
		if (p != NULL)
		    home_dir = p->pw_dir;
		else
		    home_dir = NULL;
#      endif /* !(defined HAVE_GETPWNAM_R || defined _LIBC) */ 
	    }
	    /* If we found a home directory use this.  */
	    if (home_dir != NULL) {
		char *newp;
		size_t home_len = strlen(home_dir);
		size_t rest_len = end_name == NULL ? 0 : strlen(end_name);
		newp = (char *) __alloca(home_len + rest_len + 1);
#      if defined(HAVE_MEMPCPY)
		*((char *) mempcpy(mempcpy(newp, home_dir, home_len),
				   end_name, rest_len)) = '\0';
#      else /* !(defined(HAVE_MEMPCPY)) */ 
		memcpy(newp, home_dir, home_len);
		memcpy(&newp[home_len], end_name, rest_len);
		newp[home_len + rest_len] = '\0';
#      endif /* !(defined(HAVE_MEMPCPY)) */ 
		dirname = newp;
	    }
	}
#    endif /* !defined _AMIGA && !defined WINDOWS32 */ 
    }
#  endif /* !defined(VMS) */ 

    if (__glob_pattern_p(dirname, !(flags & GLOB_NOESCAPE))) {
	/* The directory name contains metacharacters, so we
	   have to glob for the directory, and then glob for
	   the pattern in each directory found.  */
	glob_t dirs;
	register int i;

	status = glob(dirname,
		      ((flags & (GLOB_ERR | GLOB_NOCHECK | GLOB_NOESCAPE))
		       | GLOB_NOSORT | GLOB_ONLYDIR),
		      errfunc, &dirs);
	if (status != 0)
	    return status;

	/* We have successfully globbed the preceding directory name.
	   For each name we found, call glob_in_dir on it and FILENAME,
	   appending the results to PGLOB.  */
	for (i = 0; i < dirs.gl_pathc; ++i) {
	    int oldcount;

	    oldcount = pglob->gl_pathc;
	    status = glob_in_dir(filename, dirs.gl_pathv[i],
				 ((flags | GLOB_APPEND)
				  & ~(GLOB_NOCHECK | GLOB_ERR)),
				 errfunc, pglob);
	    if (status == GLOB_NOMATCH)
		/* No matches in this directory.  Try the next.  */
		continue;

	    if (status != 0) {
		globfree(&dirs);
		globfree(pglob);
		return status;
	    }

	    /* Stick the directory on the front of each name.  */
	    if (prefix_array(dirs.gl_pathv[i],
			     &pglob->gl_pathv[oldcount],
			     pglob->gl_pathc - oldcount)) {
		globfree(&dirs);
		globfree(pglob);
		return GLOB_NOSPACE;
	    }
	}

	flags |= GLOB_MAGCHAR;

	if (pglob->gl_pathc == oldcount)
	    /* No matches.  */
	    if (flags & GLOB_NOCHECK) {
		size_t len = strlen(pattern) + 1;
		char *patcopy = (char *) malloc(len);
		if (patcopy == NULL)
		    return GLOB_NOSPACE;
		memcpy(patcopy, pattern, len);

		pglob->gl_pathv
		    = (char **) realloc(pglob->gl_pathv,
					(pglob->gl_pathc +
					 ((flags & GLOB_DOOFFS) ?
					  pglob->gl_offs : 0) +
					 1 + 1) *
					sizeof(char *));
		if (pglob->gl_pathv == NULL) {
		    free(patcopy);
		    return GLOB_NOSPACE;
		}

		if (flags & GLOB_DOOFFS)
		    while (pglob->gl_pathc < pglob->gl_offs)
			pglob->gl_pathv[pglob->gl_pathc++] = NULL;

		pglob->gl_pathv[pglob->gl_pathc++] = patcopy;
		pglob->gl_pathv[pglob->gl_pathc] = NULL;
		pglob->gl_flags = flags;
	    }
	    else
		return GLOB_NOMATCH;
    }
    else {
	status = glob_in_dir(filename, dirname, flags, errfunc, pglob);
	if (status != 0)
	    return status;

	if (dirlen > 0) {
	    /* Stick the directory on the front of each name.  */
	    if (prefix_array(dirname,
			     &pglob->gl_pathv[oldcount],
			     pglob->gl_pathc - oldcount)) {
		globfree(pglob);
		return GLOB_NOSPACE;
	    }
	}
    }

    if (flags & GLOB_MARK) {
	/* Append slashes to directory names.  */
	int i;
	struct stat st;
	for (i = oldcount; i < pglob->gl_pathc; ++i)
	    if (((flags & GLOB_ALTDIRFUNC) ?
		 (*pglob->gl_stat) (pglob->gl_pathv[i], &st) :
		 __stat(pglob->gl_pathv[i], &st)) == 0 &&
		S_ISDIR(st.st_mode)) {
		size_t len = strlen(pglob->gl_pathv[i]) + 2;
		char *new = realloc(pglob->gl_pathv[i], len);
		if (new == NULL) {
		    globfree(pglob);
		    return GLOB_NOSPACE;
		}
		strcpy(&new[len - 2], "/");
		pglob->gl_pathv[i] = new;
	    }
    }

    if (!(flags & GLOB_NOSORT))
	/* Sort the vector.  */
	qsort((__ptr_t) & pglob->gl_pathv[oldcount],
	      pglob->gl_pathc - oldcount,
	      sizeof(char *), collated_compare);

    return 0;
}


/* Free storage allocated in PGLOB by a previous `glob' call.  */
void globfree(pglob)
     register glob_t *pglob;
{
    if (pglob->gl_pathv != NULL) {
	register int i;
	for (i = 0; i < pglob->gl_pathc; ++i)
	    if (pglob->gl_pathv[i] != NULL)
		free((__ptr_t) pglob->gl_pathv[i]);
	free((__ptr_t) pglob->gl_pathv);
    }
}


/* Do a collated comparison of A and B.  */
static int collated_compare(a, b)
     const __ptr_t a;
     const __ptr_t b;
{
    const char *const s1 = *(const char *const *const) a;
    const char *const s2 = *(const char *const *const) b;

    if (s1 == s2)
	return 0;
    if (s1 == NULL)
	return 1;
    if (s2 == NULL)
	return -1;
    return strcoll(s1, s2);
}


/* Prepend DIRNAME to each of N members of ARRAY, replacing ARRAY's
   elements in place.  Return nonzero if out of memory, zero if successful.
   A slash is inserted between DIRNAME and each elt of ARRAY,
   unless DIRNAME is just "/".  Each old element of ARRAY is freed.  */
static int prefix_array(dirname, array, n)
     const char *dirname;
     char **array;
     size_t n;
{
    register size_t i;
    size_t dirlen = strlen(dirname);

    if (dirlen == 1 && dirname[0] == '/')
	/* DIRNAME is just "/", so normal prepending would get us "//foo".
	   We want "/foo" instead, so don't prepend any chars from DIRNAME.  */
	dirlen = 0;

    for (i = 0; i < n; ++i) {
	size_t eltlen = strlen(array[i]) + 1;
	char *new = (char *) malloc(dirlen + 1 + eltlen);
	if (new == NULL) {
	    while (i > 0)
		free((__ptr_t) array[--i]);
	    return 1;
	}

#  if defined(HAVE_MEMPCPY)
	{
	    char *endp = (char *) mempcpy(new, dirname, dirlen);
	    *endp++ = '/';
	    mempcpy(endp, array[i], eltlen);
	}
#  else /* !(defined(HAVE_MEMPCPY)) */ 
	memcpy(new, dirname, dirlen);
	new[dirlen] = '/';
	memcpy(&new[dirlen + 1], array[i], eltlen);
#  endif /* !(defined(HAVE_MEMPCPY)) */ 
	free((__ptr_t) array[i]);
	array[i] = new;
    }

    return 0;
}


/* Return nonzero if PATTERN contains any metacharacters.
   Metacharacters can be quoted with backslashes if QUOTE is nonzero.  */
int __glob_pattern_p(pattern, quote)
     const char *pattern;
     int quote;
{
    register const char *p;
    int open = 0;

    for (p = pattern; *p != '\0'; ++p)
	switch (*p) {
	case '?':
	case '*':
	    return 1;

	case '\\':
	    if (quote && p[1] != '\0')
		++p;
	    break;

	case '[':
	    open = 1;
	    break;

	case ']':
	    if (open)
		return 1;
	    break;
	}

    return 0;
}
#  if defined(_LIBC)
weak_alias(__glob_pattern_p, glob_pattern_p)
#  endif /* defined(_LIBC) */ 


/* Like `glob', but PATTERN is a final pathname component,
   and matches are searched for in DIRECTORY.
   The GLOB_NOSORT bit in FLAGS is ignored.  No sorting is ever done.
   The GLOB_APPEND flag is assumed to be set (always appends).  */
     static int
         glob_in_dir(pattern, directory, flags, errfunc, pglob)
     const char *pattern;
     const char *directory;
     int flags;
     int (*errfunc) __P((const char *, int));
     glob_t *pglob;
{
    __ptr_t stream;

    struct globlink {
	struct globlink *next;
	char *name;
    };
    struct globlink *names = NULL;
    size_t nfound;
    int meta;
    int save;

    stream = ((flags & GLOB_ALTDIRFUNC) ?
	      (*pglob->gl_opendir) (directory) :
	      (__ptr_t) opendir(directory));
    if (stream == NULL) {
	if ((errfunc != NULL && (*errfunc) (directory, errno)) ||
	    (flags & GLOB_ERR))
	    return GLOB_ABORTED;
	nfound = 0;
	meta = 0;
    }
    else if (pattern[0] == '\0') {
	/* This is a special case for matching directories like in
	   "*a/".  */
	names = (struct globlink *) __alloca(sizeof(struct globlink));
	names->name = (char *) malloc(1);
	if (names->name == NULL)
	    goto memory_error;
	names->name[0] = '\0';
	names->next = NULL;
	nfound = 1;
	meta = 0;
    }
    else {
	nfound = 0;
	meta = __glob_pattern_p(pattern, !(flags & GLOB_NOESCAPE));
	if (meta)
	    flags |= GLOB_MAGCHAR;

	while (1) {
	    const char *name;
	    size_t len;
	    struct dirent *d = ((flags & GLOB_ALTDIRFUNC) ?
				(*pglob->gl_readdir) (stream) :
				readdir((DIR *) stream));
	    if (d == NULL)
		break;
	    if (!REAL_DIR_ENTRY(d))
		continue;

#  if defined(HAVE_D_TYPE)
	    /* If we shall match only directories use the information
	       provided by the dirent call if possible.  */
	    if ((flags & GLOB_ONLYDIR)
		&& d->d_type != DT_UNKNOWN && d->d_type != DT_DIR)
		continue;
#  endif /* defined(HAVE_D_TYPE) */ 

	    name = d->d_name;

	    if ((!meta && strcmp(pattern, name) == 0)
		|| wu_fnmatch(pattern, name,
			      (!(flags & GLOB_PERIOD) ? FNM_PERIOD : 0) |
			      ((flags & GLOB_NOESCAPE) ? FNM_NOESCAPE : 0)
#  if defined(_AMIGA)
			      | FNM_CASEFOLD
#  endif /* defined(_AMIGA) */ 
		) == 0) {
		struct globlink *new
		= (struct globlink *) __alloca(sizeof(struct globlink));
		len = NAMLEN(d);
		new->name = (char *) malloc(len + 1);
		if (new->name == NULL)
		    goto memory_error;
#  if defined(HAVE_MEMPCPY)
		*((char *) mempcpy((__ptr_t) new->name, name, len)) = '\0';
#  else /* !(defined(HAVE_MEMPCPY)) */ 
		memcpy((__ptr_t) new->name, name, len);
		new->name[len] = '\0';
#  endif /* !(defined(HAVE_MEMPCPY)) */ 
		new->next = names;
		names = new;
		++nfound;
		if (!meta)
		    break;
	    }
	}
    }

    if (nfound == 0 && (flags & GLOB_NOMAGIC) && !meta)
	flags |= GLOB_NOCHECK;

    if (nfound == 0 && (flags & GLOB_NOCHECK)) {
	size_t len = strlen(pattern);
	nfound = 1;
	names = (struct globlink *) __alloca(sizeof(struct globlink));
	names->next = NULL;
	names->name = (char *) malloc(len + 1);
	if (names->name == NULL)
	    goto memory_error;
#  if defined(HAVE_MEMPCPY)
	*((char *) mempcpy(names->name, pattern, len)) = '\0';
#  else /* !(defined(HAVE_MEMPCPY)) */ 
	memcpy(names->name, pattern, len);
	names->name[len] = '\0';
#  endif /* !(defined(HAVE_MEMPCPY)) */ 
    }

    if (nfound != 0) {
	pglob->gl_pathv
	    = (char **) realloc(pglob->gl_pathv,
				(pglob->gl_pathc +
			      ((flags & GLOB_DOOFFS) ? pglob->gl_offs : 0) +
				 nfound + 1) *
				sizeof(char *));
	if (pglob->gl_pathv == NULL)
	    goto memory_error;

	if (flags & GLOB_DOOFFS)
	    while (pglob->gl_pathc < pglob->gl_offs)
		pglob->gl_pathv[pglob->gl_pathc++] = NULL;

	for (; names != NULL; names = names->next)
	    pglob->gl_pathv[pglob->gl_pathc++] = names->name;
	pglob->gl_pathv[pglob->gl_pathc] = NULL;

	pglob->gl_flags = flags;
    }

    save = errno;
    if (flags & GLOB_ALTDIRFUNC)
	(*pglob->gl_closedir) (stream);
    else
	closedir((DIR *) stream);
    __set_errno(save);

    return nfound == 0 ? GLOB_NOMATCH : 0;

  memory_error:
    {
	int save = errno;
	if (flags & GLOB_ALTDIRFUNC)
	    (*pglob->gl_closedir) (stream);
	else
	    closedir((DIR *) stream);
	__set_errno(save);
    }
    while (names != NULL) {
	if (names->name != NULL)
	    free((__ptr_t) names->name);
	names = names->next;
    }
    return GLOB_NOSPACE;
}

#endif /* !defined(ELIDE_CODE) */ 

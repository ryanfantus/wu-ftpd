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
 
  $Id: wuftpd_glob.h,v 1.9 2011/10/20 22:58:13 wmaton Exp $
 
****************************************************************************/
#if !defined(_GLOB_H)
#  define _GLOB_H	1

#  if defined(__cplusplus)
extern "C"
{
#  endif /* defined(__cplusplus) */ 

#  undef __ptr_t
#  if (defined __cplusplus || (defined __STDC__ && __STDC__) \
     || defined WINDOWS32)
#    undef __P
#    define __P(protos)	protos
#    define __ptr_t	void *
#    if !defined __GNUC__ || __GNUC__ < 2
#      undef __const
#      define __const const
#    endif /* !defined __GNUC__ || __GNUC__ < 2 */ 
#  else /* !((defined __cplusplus || (defined __STDC__ && __STDC__) \) */ 
#    undef __P
#    define __P(protos)	()
#    undef __const
#    define __const
#    define __ptr_t	char *
#  endif /* !((defined __cplusplus || (defined __STDC__ && __STDC__) \) */ 

/* Bits set in the FLAGS argument to `glob'.  */
#  define GLOB_ERR	(1 << 0)	/* Return on read errors.  */
#  define GLOB_MARK	(1 << 1)	/* Append a slash to each name.  */
#  define GLOB_NOSORT	(1 << 2)	/* Don't sort the names.  */
#  define GLOB_DOOFFS	(1 << 3)	/* Insert PGLOB->gl_offs NULLs.  */
#  define GLOB_NOCHECK	(1 << 4)	/* If nothing matches, return the pattern.  */
#  define GLOB_APPEND	(1 << 5)	/* Append to results of a previous call.  */
#  define GLOB_NOESCAPE	(1 << 6)	/* Backslashes don't quote metacharacters.  */
#  define GLOB_PERIOD	(1 << 7)	/* Leading `.' can be matched by metachars.  */

#  if (!defined _POSIX_C_SOURCE || _POSIX_C_SOURCE < 2 || defined _BSD_SOURCE \
     || defined _GNU_SOURCE)
#    define GLOB_MAGCHAR	 (1 << 8)	/* Set in gl_flags if any metachars seen.  */
#    define GLOB_ALTDIRFUNC (1 << 9)	/* Use gl_opendir et al functions.  */
#    define GLOB_BRACE	 (1 << 10)	/* Expand "{a,b}" to "a" "b".  */
#    define GLOB_NOMAGIC	 (1 << 11)	/* If no magic chars, return the pattern.  */
#    define GLOB_TILDE	 (1 << 12)	/* Expand ~user and ~ to home directories. */
#    define GLOB_ONLYDIR	 (1 << 13)	/* Match only directories.  */
#    define __GLOB_FLAGS	(GLOB_ERR|GLOB_MARK|GLOB_NOSORT|GLOB_DOOFFS| \
			 GLOB_NOESCAPE|GLOB_NOCHECK|GLOB_APPEND|     \
			 GLOB_PERIOD|GLOB_ALTDIRFUNC|GLOB_BRACE|     \
			 GLOB_NOMAGIC|GLOB_TILDE|GLOB_ONLYDIR)
#  else /* !((!defined _POSIX_C_SOURCE || _POSIX_C_SOURCE < 2 || defined _BSD_SOURCE \) */ 
#    define __GLOB_FLAGS	(GLOB_ERR|GLOB_MARK|GLOB_NOSORT|GLOB_DOOFFS| \
			 GLOB_NOESCAPE|GLOB_NOCHECK|GLOB_APPEND|     \
			 GLOB_PERIOD)
#  endif /* !((!defined _POSIX_C_SOURCE || _POSIX_C_SOURCE < 2 || defined _BSD_SOURCE \) */ 

/* Error returns from `glob'.  */
#  define GLOB_NOSPACE	1	/* Ran out of memory.  */
#  define GLOB_ABORTED	2	/* Read error.  */
#  define GLOB_NOMATCH	3	/* No matches found.  */

#  if defined(_GNU_SOURCE)
/* Previous versions of this file defined GLOB_ABEND instead of
   GLOB_ABORTED.  Provide a compatibility definition here.  */
#    define GLOB_ABEND GLOB_ABORTED
#  endif /* defined(_GNU_SOURCE) */ 

/* Structure describing a globbing run.  */
#  if !defined _AMIGA && !defined VMS	/* Buggy compiler.   */
    struct stat;
#  endif /* !defined _AMIGA && !defined VMS	/* Buggy compiler.   */ */ 
    typedef struct {
	int gl_pathc;		/* Count of paths matched by the pattern.  */
	char **gl_pathv;	/* List of matched pathnames.  */
	int gl_offs;		/* Slots to reserve in `gl_pathv'.  */
	int gl_flags;		/* Set to FLAGS, maybe | GLOB_MAGCHAR.  */

	/* If the GLOB_ALTDIRFUNC flag is set, the following functions
	   are used instead of the normal file access functions.  */
	void (*gl_closedir) __P((void *));
	struct dirent *(*gl_readdir) __P((void *));
	       __ptr_t(*gl_opendir) __P((__const char *));
	int (*gl_lstat) __P((__const char *, struct stat *));
	int (*gl_stat) __P((__const char *, struct stat *));
    } glob_t;

/* Do glob searching for PATTERN, placing results in PGLOB.
   The bits defined above may be set in FLAGS.
   If a directory cannot be opened or read and ERRFUNC is not nil,
   it is called with the pathname that caused the error, and the
   `errno' value from the failing call; if it returns non-zero
   `glob' returns GLOB_ABEND; if it returns zero, the error is ignored.
   If memory cannot be allocated for PGLOB, GLOB_NOSPACE is returned.
   Otherwise, `glob' returns zero.  */
    extern int glob __P((__const char *__pattern, int __flags,
			 int  (*__errfunc) __P((__const char *, int)),
			 glob_t * __pglob));

/* Free storage allocated in PGLOB by a previous `glob' call.  */
    extern void globfree __P((glob_t * __pglob));


#  if defined(_GNU_SOURCE)
/* Return nonzero if PATTERN contains any metacharacters.
   Metacharacters can be quoted with backslashes if QUOTE is nonzero.

   This function is not part of the interface specified by POSIX.2
   but several programs want to use it.  */
    extern int __glob_pattern_p __P((__const char *__pattern, int __quote));
    extern int glob_pattern_p __P((__const char *__pattern, int __quote));
#  endif /* defined(_GNU_SOURCE) */ 

#  if defined(__cplusplus)
}

#  endif /* defined(__cplusplus) */ 
#endif /* !defined(_GLOB_H) */ 

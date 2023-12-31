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
   
  $Id: popen.c,v 1.9 2011/10/20 22:58:11 wmaton Exp $  
   
****************************************************************************/
#include "config.h"

#include <sys/types.h>
#include <sys/param.h>
#include <sys/wait.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <limits.h>
#if defined(HAVE_FCNTL_H)
#  include <fcntl.h>
#endif /* defined(HAVE_FCNTL_H) */ 
#include "pathnames.h"
#include "proto.h"

#if !defined(NCARGS)
#  define NCARGS	20480		/* at least on SGI IRIX */
#endif /* !defined(NCARGS) */ 

/* 
 * Special version of popen which avoids call to shell.  This insures noone
 * may create a pipe to a hidden program as a side effect of a list or dir
 * command. 
 */
static int popen_fd = -1;
static pid_t popen_pid = -1;
#define MAX_ARGV 100
#define MAX_GARGV (NCARGS/6)

FILE *ftpd_popen(char *program, char *type, int closestderr)
{
    register char *cp;
    FILE *iop;
    int argc, gargc, pdes[2], i, devnullfd;
    char **pop, *argv[MAX_ARGV], *gargv[MAX_GARGV], *vv[2];
    extern char *globerr;

    /*
     * ftpd never needs more than one pipe open at a time, so only one file
     * descriptor and one process ID are stored (in popen_fd and popen_pid).
     * Protect against multiple pipes in case this changes.
     */
    if (popen_fd != -1)
	return (NULL);

    if ((*type != 'r' && *type != 'w') || type[1])
	return (NULL);

    if (pipe(pdes) < 0)
	return (NULL);

    /* empty the array */
    (void) memset((void *) argv, 0, sizeof(argv));
    /* break up string into pieces */
    for (argc = 0, cp = program; argc < MAX_ARGV - 1; cp = NULL)
	if (!(argv[argc++] = strtok(cp, " \t\n")))
	    break;

    /* glob each piece */
    gargv[0] = argv[0];
    for (gargc = argc = 1; argc < MAX_ARGV && argv[argc]; argc++) {
	if (!(pop = ftpglob(argv[argc])) || globerr != NULL) {	/* globbing failed */
	    if (pop) {
		blkfree(pop);
		free((char *) pop);
	    }
	    vv[0] = strspl(argv[argc], "");
	    vv[1] = NULL;
	    pop = copyblk(vv);
	}
	argv[argc] = (char *) pop;	/* save to free later */
	while (*pop && gargc < (MAX_GARGV - 1))
	    gargv[gargc++] = *pop++;
    }
    gargv[gargc] = NULL;

#if defined(SIGCHLD)
    (void) signal(SIGCHLD, SIG_DFL);
#endif /* defined(SIGCHLD) */ 
    iop = NULL;
    switch (popen_pid = vfork()) {
    case -1:			/* error */
	(void) close(pdes[0]);
	(void) close(pdes[1]);
	goto pfree;
	/* NOTREACHED */
    case 0:			/* child */
	if (*type == 'r') {
	    if (pdes[1] != 1) {
		dup2(pdes[1], 1);
		if (closestderr) {
		    (void) close(2);
		    /* stderr output is written to fd 2, so make sure it isn't
		     * available to be assigned to another file */
		    if ((devnullfd = open(_PATH_DEVNULL, O_RDWR)) != -1) {
			if (devnullfd != 2) {
			    dup2(devnullfd, 2);
			    (void) close(devnullfd);
			}
		    }
		}
		else
		    dup2(pdes[1], 2);	/* stderr, too! */
		(void) close(pdes[1]);
	    }
	    (void) close(pdes[0]);
	}
	else {
	    if (pdes[0] != 0) {
		dup2(pdes[0], 0);
		(void) close(pdes[0]);
	    }
	    (void) close(pdes[1]);
	}
	closefds(3);
	/* begin CERT suggested fixes */
	close(0);
	i = geteuid();
	delay_signaling();	/* we can't allow any signals while euid==0: kinch */
	seteuid(0);
	setgid(getegid());
	setuid(i);
	enable_signaling();	/* we can allow signals once again: kinch */
	/* end CERT suggested fixes */
	execv(gargv[0], gargv);
	perror(gargv[0]);
	_exit(1);
    }
    /* parent; assume fdopen can't fail...  */
    if (*type == 'r') {
	iop = fdopen(pdes[0], type);
	(void) close(pdes[1]);
    }
    else {
	iop = fdopen(pdes[1], type);
	(void) close(pdes[0]);
    }
    popen_fd = fileno(iop);

  pfree:for (argc = 1; argc < MAX_ARGV && argv[argc]; argc++) {
	blkfree((char **) argv[argc]);
	free((char *) argv[argc]);
    }
    return (iop);
}

int ftpd_pclose(FILE *iop)
{
    pid_t pid;
#if defined(HAVE_SIGPROCMASK) || (defined(SVR4) && !defined(AUTOCONF))
    sigset_t sig, omask;
    int stat_loc;
    sigemptyset(&sig);
    sigaddset(&sig, SIGINT);
    sigaddset(&sig, SIGQUIT);
    sigaddset(&sig, SIGHUP);
#  elif defined (_OSF_SOURCE)
    int omask;
    int status;
#else /* !(defined(HAVE_SIGPROCMASK) || (defined(SVR4) && !defined(AUTOCONF))) */ 
    int omask;
    union wait stat_loc;
#endif /* !(defined(HAVE_SIGPROCMASK) || (defined(SVR4) && !defined(AUTOCONF))) */ 

    /* pclose returns -1 if stream is not associated with a `popened'
     * command, or, if already `pclosed'. */
    if ((popen_fd == -1) || (popen_fd != fileno(iop)))
	return (-1);
    (void) fclose(iop);
#if defined(HAVE_SIGPROCMASK) || (!defined(AUTOCONF) && defined(SVR4))
    sigprocmask(SIG_BLOCK, &sig, &omask);
#else /* !(defined(HAVE_SIGPROCMASK) || (!defined(AUTOCONF) && defined(SVR4))) */ 
    omask = sigblock(sigmask(SIGINT) | sigmask(SIGQUIT) | sigmask(SIGHUP));
#endif /* !(defined(HAVE_SIGPROCMASK) || (!defined(AUTOCONF) && defined(SVR4))) */ 

#if (!defined(HAVE_SIGPROCMASK) || (!defined(SVR4) && !defined(AUTOCONF))) && defined (_OSF_SOURCE)
    while ((pid = wait(&status)) != popen_pid && pid != -1);
#  elif ! defined(NeXT)
    while ((pid = wait((int *) &stat_loc)) != popen_pid && pid != -1);
#else /* !((!defined(HAVE_SIGPROCMASK) || (!defined(SVR4) && !defined(AUTOCONF))) && defined (_OSF_SOURCE)) */ 
    while ((pid = wait(&stat_loc)) != popen_pid && pid != -1);
#endif /* !((!defined(HAVE_SIGPROCMASK) || (!defined(SVR4) && !defined(AUTOCONF))) && defined (_OSF_SOURCE)) */ 
    popen_pid = -1;
    popen_fd = -1;
#if defined(SIGCHLD)
    (void) signal(SIGCHLD, SIG_IGN);
#endif /* defined(SIGCHLD) */ 
#if defined(HAVE_SIGPROCMASK) || (defined(SVR4) && !defined(AUTOCONF))
    sigprocmask(SIG_SETMASK, &omask, (sigset_t *) NULL);
    return (pid == -1 ? -1 : WEXITSTATUS(stat_loc));
#else /* !(defined(HAVE_SIGPROCMASK) || (defined(SVR4) && !defined(AUTOCONF))) */ 
    (void) sigsetmask(omask);
#  if defined(_OSF_SOURCE)
    return (pid == -1 ? -1 : status);
#    elif defined(LINUX)
    return (pid == -1 ? -1 : WEXITSTATUS(stat_loc));
#  else /* !(defined(_OSF_SOURCE)) */ 
    return (pid == -1 ? -1 : stat_loc.w_status);
#  endif /* !(defined(_OSF_SOURCE)) */ 
#endif /* !(defined(HAVE_SIGPROCMASK) || (defined(SVR4) && !defined(AUTOCONF))) */ 
}

#if defined(CLOSEFROM)
void closefds(int startfd)
{
    closefrom(startfd);
}
#else /* !(defined(CLOSEFROM)) */ 

#if defined(HAVE_GETRLIMIT)
#  include <sys/resource.h>
#endif /* defined(HAVE_GETRLIMIT) */ 

void closefds(int startfd)
{
    int i, fds;
#if defined(HAVE_GETRLIMIT) && defined(RLIMIT_NOFILE)
    struct rlimit rlp;
#endif /* !(defined(HAVE_GETRLIMIT) && defined(RLIMIT_NOFILE)) */ 

#if defined(OPEN_MAX)
    fds = OPEN_MAX;
#else /* !(defined(OPEN_MAX)) */ 
    fds = 31;
#endif /* !(defined(OPEN_MAX)) */ 

#if defined(HAVE_GETRLIMIT) && defined(RLIMIT_NOFILE)
    if ((getrlimit(RLIMIT_NOFILE, &rlp) == 0) &&
	(rlp.rlim_cur != RLIM_INFINITY)) {
	fds = rlp.rlim_cur;
    }
#else /* !(defined(HAVE_GETRLIMIT) && defined(RLIMIT_NOFILE)) */ 
#  if defined(HAVE_GETDTABLESIZE)
    if ((i = getdtablesize()) > 0)
	fds = i;
#  else /* !(defined(HAVE_GETDTABLESIZE)) */ 
#    if defined(HAVE_SYSCONF)
    fds = sysconf(_SC_OPEN_MAX);
#    endif /* !(defined(HAVE_SYSCONF)) */ 
#  endif /* !(defined(HAVE_GETDTABLESIZE)) */ 
#endif /* !(defined(HAVE_GETRLIMIT) && defined(RLIMIT_NOFILE)) */ 

    for (i = startfd; i < fds; i++)
	close(i);
}
#endif /* !(defined(CLOSEFROM)) */ 

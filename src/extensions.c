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
 
  $Id: extensions.c,v 1.13 2011/10/20 23:54:41 wmaton Exp $
 
****************************************************************************/

/****************************************************************************
**
** Extensions to the wu-ftpd server itself.  This has nothing to do with
** FTP extensions per RFCs.
**
****************************************************************************/

#include "config.h"

#include <stdio.h>
#include <errno.h>
#include <string.h>

#if defined(HAVE_SYS_SYSLOG_H)
#  include <sys/syslog.h>
#endif /* defined(HAVE_SYS_SYSLOG_H) */ 
#if defined(HAVE_SYSLOG_H) || (!defined(AUTOCONF) && !defined(HAVE_SYS_SYSLOG_H))
#  include <syslog.h>
#endif /* defined(HAVE_SYSLOG_H) || (!defined(AUTOCONF) && !defined(HAVE_SYS_SYSLOG_H)) */ 

#if defined(TIME_WITH_SYS_TIME)
#  include <time.h>
#  include <sys/time.h>
#else /* !(defined(TIME_WITH_SYS_TIME)) */ 
#  if defined(HAVE_SYS_TIME_H)
#    include <sys/time.h>
#  else /* !(defined(HAVE_SYS_TIME_H)) */ 
#    include <time.h>
#  endif /* !(defined(HAVE_SYS_TIME_H)) */ 
#endif /* !(defined(TIME_WITH_SYS_TIME)) */ 
#include <pwd.h>
#include <setjmp.h>
#include <grp.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <sys/param.h>

#if defined(HAVE_SYS_FS_UFS_QUOTA_H)
#  include <sys/fs/ufs_quota.h>
#  elif defined(HAVE_UFS_UFS_QUOTA_H)
#  include <ufs/ufs/quota.h>
#  elif defined(HAVE_UFS_QUOTA_H)
#  include <ufs/quota.h>
#  elif defined(HAVE_JFS_QUOTA_H)
#  include <jfs/quota.h>
#endif /* defined(HAVE_SYS_FS_UFS_QUOTA_H) */ 

#if defined(HAVE_SYS_MNTTAB_H)
#  include <sys/mnttab.h>
#  elif defined(HAVE_SYS_MNTENT_H)
#  include <sys/mntent.h>
#endif /* defined(HAVE_SYS_MNTTAB_H) */ 

#if defined(HAVE_STATVFS)
#  include <sys/statvfs.h>
#  elif defined(HAVE_SYS_VFS)
#  include <sys/vfs.h>
#  elif defined(HAVE_SYS_MOUNT)
#  include <sys/mount.h>
#endif /* defined(HAVE_STATVFS) */ 

#include "ftp.h"

#if defined(HAVE_PATHS_H)
#  include <paths.h>
#endif /* defined(HAVE_PATHS_H) */ 
#include "pathnames.h"
#include "extensions.h"
#include "wu_fnmatch.h"
#include "proto.h"

#include "wuftpd_ftw.h"

#if defined(QUOTA)
struct dqblk quota;
char *time_quota(long curstate, long softlimit, long timelimit, char *timeleft);
#endif /* defined(QUOTA) */ 

#if defined(HAVE_REGEX_H)
#  include <regex.h>
#endif /* defined(HAVE_REGEX_H) */ 

#if defined(HAVE_REGEX) && defined(SVR4) && ! (defined(NO_LIBGEN))
#  include <libgen.h>
#endif /* defined(HAVE_REGEX) && defined(SVR4) && ! (defined(NO_LIBGEN)) */ 

extern int type, transflag, ftwflag, authenticated, autospout_free, data,
    pdata, anonymous, guest;
extern char chroot_path[], guestpw[];

#if defined(TRANSFER_COUNT)
extern off_t data_count_in;
extern off_t data_count_out;
#  if defined(TRANSFER_LIMIT)
extern off_t data_limit_raw_in;
extern off_t data_limit_raw_out;
extern off_t data_limit_raw_total;
extern off_t data_limit_data_in;
extern off_t data_limit_data_out;
extern off_t data_limit_data_total;
#    if defined(RATIO) /* 1998/08/06 K.Wakui */
#      define TRUNC_KB(n)   ((n)/1024+(((n)%1024)?1:0))
extern time_t	login_time;
extern time_t	limit_time;
extern off_t    total_free_dl;
extern int      upload_download_rate;
#    endif /* defined(RATIO) - 1998-08-06 K.Wakui */ 
#  endif /* defined(TRANSFER_LIMIT) */ 
#endif /* defined(TRANSFER_COUNT) */ 

#if defined(OTHER_PASSWD)
#  include "getpwnam.h"
extern char _path_passwd[];
#endif /* defined(OTHER_PASSWD) */ 

extern char the_user[];
char *match_class_user(char *argv[], int *i, char *class, char *realname, char *localname);

extern char *globerr, remotehost[];
#if defined(THROUGHPUT)
extern char remoteaddr[];
#endif /* defined(THROUGHPUT) */ 

#if !defined(HAVE_REGEX)
char *re_comp(const char *regex);
int re_exec(const char *p1);
#endif /* !defined(HAVE_REGEX) */ 

char shuttime[30], denytime[30], disctime[30];

FILE *dout;

time_t newer_time;

int show_fullinfo;

/* This always was a bug, because neither st_size nor time_t were required to
   be compatible with int, but needs fixing properly for C9X. */

/* Some systems use one format, some another.  This takes care of the garbage */
#if !defined(L_FORMAT)		/* Autoconf detects this... */
#  if (defined(BSD) && (BSD >= 199103)) && !defined(LONGOFF_T)
#    define L_FORMAT "qd"
#  else /* !((defined(BSD) && (BSD >= 199103)) && !defined(LONGOFF_T)) */ 
#    if defined(_AIX42)
#      define L_FORMAT "lld"
#    else /* !(defined(_AIX42)) */ 
#      if defined(SOLARIS_2)
#        define L_FORMAT "ld"
#      else /* !(defined(SOLARIS_2)) */ 
#        define L_FORMAT "d"
#      endif /* !(defined(SOLARIS_2)) */ 
#    endif /* !(defined(_AIX42)) */ 
#  endif /* !((defined(BSD) && (BSD >= 199103)) && !defined(LONGOFF_T)) */ 
#endif /* !defined(L_FORMAT) - Autoconf detects this... */

#if !defined(T_FORMAT)
#  define T_FORMAT "d"
#endif /* !defined(T_FORMAT) */ 
#if !defined(PW_UID_FORMAT)
#  define PW_UID_FORMAT "d"
#endif /* !defined(PW_UID_FORMAT) */ 
#if !defined(GR_GID_FORMAT)
#  define GR_GID_FORMAT "d"
#endif /* !defined(GR_GID_FORMAT) */ 

#if !defined(HAVE_SNPRINTF)
int snprintf(char *str, size_t count, const char *fmt,...);
#endif /* !defined(HAVE_SNPRINTF) */ 

#if defined(SITE_NEWER)
int check_newer(const char *path, const struct stat *st, int flag)
{
    if (st->st_mtime > newer_time) {
	if (show_fullinfo != 0) {
	    if (flag == FTW_F || flag == FTW_D) {
		fprintf(dout, "%s %" L_FORMAT " %" T_FORMAT " %s\n",
			flag == FTW_F ? "F" : "D",
			st->st_size, st->st_mtime, path);
	    }
	}
	else if (flag == FTW_F)
	    fprintf(dout, "%s\n", path);
    }

    /* When an ABOR has been received (which sets ftwflag > 1) return a
     * non-zero value which causes ftw to stop tree traversal and return.
     */

    return (ftwflag > 1 ? 1 : 0);
}
#endif /* defined(SITE_NEWER) */ 

#if defined(HAVE_STATVFS)
long getSize(char *s)
{
    struct statvfs buf;

    if (statvfs(s, &buf) != 0)
	return (0);

    return (buf.f_bavail * buf.f_frsize / 1024);
}
#  elif defined(HAVE_SYS_VFS) || defined (HAVE_SYS_MOUNT)
long getSize(char *s)
{
    struct statfs buf;

    if (statfs(s, &buf) != 0)
	return (0);

    return (buf.f_bavail * buf.f_bsize / 1024);
}
#endif /* defined(HAVE_STATVFS) */ 

/*************************************************************************/
/* FUNCTION  : msg_massage                                               */
/* PURPOSE   : Scan a message line for magic cookies, replacing them as  */
/*             needed.                                                   */
/* ARGUMENTS : pointer input and output buffers                          */
/*************************************************************************/

void msg_massage(const char *inbuf, char *outbuf, size_t outlen)
{
    const char *inptr = inbuf;
    char *outptr = outbuf;
#if defined(QUOTA)
    char timeleft[TIMELEFTLEN];
#endif /* defined(QUOTA) */ 
    char buffer[MAXPATHLEN];
    time_t curtime;
    int limit;
#if !defined(LOG_FAILED) || defined(QUOTA)
    extern struct passwd *pw;
#endif /* !defined(LOG_FAILED) || defined(QUOTA) */ 
    struct aclmember *entry;

#if defined(VIRTUAL)
    extern int virtual_mode;
    extern int virtual_ftpaccess;
    extern char virtual_email[];
#endif /* defined(VIRTUAL) */ 
    extern char hostname[];
    extern char authuser[];

    (void) acl_getclass(buffer, sizeof(buffer));
    limit = acl_getlimit(buffer, NULL, 0);

#if defined(QUOTA) /* Better than calling it for each related cookie */
    if (pw != NULL)
	get_quota(pw->pw_dir, pw->pw_uid);
#endif /* defined(QUOTA) -  Better than calling it for each related cookie */

    while ((outlen > 1) && (*inptr != '\0')) {
	if (*inptr != '%') {
	    *outptr++ = *inptr;
	    outlen -= 1;
	}
	else {
	    entry = NULL;
	    switch (*++inptr) {
	    case 'E':
#if defined(VIRTUAL)
		if (virtual_mode && !virtual_ftpaccess && virtual_email[0] != '\0')
		    snprintf(outptr, outlen, "%s", virtual_email);
		else
#endif /* defined(VIRTUAL) */ 
		if ((getaclentry("email", &entry)) && ARG0)
		    snprintf(outptr, outlen, "%s", ARG0);
		else
		    *outptr = '\0';
		break;

	    case 'N':
		snprintf(outptr, outlen, "%d", acl_countusers(buffer));
		break;

	    case 'M':
		if (limit == -1)
		    strlcpy(outptr, "unlimited", outlen);
		else
		    snprintf(outptr, outlen, "%d", limit);
		break;

	    case 'T':
		(void) time(&curtime);
		strlcpy(outptr, ctime(&curtime), outlen);
		if (outlen > 24)
		    *(outptr + 24) = '\0';
		break;

	    case 'F':
#if defined(HAVE_STATVFS) || defined(HAVE_SYS_VFS) || defined(HAVE_SYS_MOUNT)
		snprintf(outptr, outlen, "%lu", (long) getSize("."));
#else /* !(defined(HAVE_STATVFS) || defined(HAVE_SYS_VFS) || defined(HAVE_SYS_MOUNT)) */ 
		*outptr = '\0';
#endif /* !(defined(HAVE_STATVFS) || defined(HAVE_SYS_VFS) || defined(HAVE_SYS_MOUNT)) */ 
		break;

	    case 'C':
#if defined(HAVE_GETCWD)
		(void) getcwd(outptr, outlen);
#else /* !(defined(HAVE_GETCWD)) */ 
#  error wu-ftpd on this platform has security deficiencies!!!
		(void) getwd(outptr);
#endif /* !(defined(HAVE_GETCWD)) */ 
		break;

	    case 'R':
		strlcpy(outptr, remotehost, outlen);
		break;

	    case 'L':
		strlcpy(outptr, hostname, outlen);
		break;

	    case 'U':
		if (xferdone && anonymous)
		    strlcpy(outptr, guestpw, outlen);
		else
#if defined(LOG_FAILED)
		    strlcpy(outptr, the_user, outlen);
#else /* !(defined(LOG_FAILED)) */ 
		    strlcpy(outptr,
			    (pw == NULL) ? "[unknown]" : pw->pw_name, outlen);
#endif /* !(defined(LOG_FAILED)) */ 
		break;

	    case 's':
		strlcpy(outptr, shuttime, outlen);
		if (outlen > 24)
		    *(outptr + 24) = '\0';
		break;

	    case 'd':
		strlcpy(outptr, disctime, outlen);
		if (outlen > 24)
		    *(outptr + 24) = '\0';
		break;

	    case 'r':
		strlcpy(outptr, denytime, outlen);
		if (outlen > 24)
		    *(outptr + 24) = '\0';
		break;

/* KH : cookie %u for RFC931 name */
	    case 'u':
		if (authenticated)
		    strlcpy(outptr, authuser, outlen);
		else {
		    if (xferdone)
			snprintf(outptr, outlen, "%c", '*');
		    else
			strlcpy(outptr, "[unknown]", outlen);
		}
		break;

#if defined(QUOTA)
	    case 'B':
		if (pw == NULL) {
		    strlcpy(outptr, "[unknown]", outlen);
		    break;
		}
#  if defined(QUOTA_BLOCKS) || defined(HAS_NO_QUOTACTL)	
		/* 1024-blocks instead of 512-blocks */
		snprintf(outptr, outlen, "%ld", quota.dqb_bhardlimit % 2 ?
			 (long) (quota.dqb_bhardlimit / 2 + 1) : (long) (quota.dqb_bhardlimit / 2));
#  else /* !(defined(QUOTA_BLOCKS) || defined(HAS_NO_QUOTACTL)	) */ 
		snprintf(outptr, outlen, "%ld", (long) quota.dqb_bhardlimit);
#  endif /* !(defined(QUOTA_BLOCKS) || defined(HAS_NO_QUOTACTL)	) */ 
		break;

	    case 'b':
		if (pw == NULL) {
		    strlcpy(outptr, "[unknown]", outlen);
		    break;
		}
#  if defined(QUOTA_BLOCKS) || defined(HAS_NO_QUOTACTL)	
		/* 1024-blocks instead of 512-blocks */
		snprintf(outptr, outlen, "%ld", quota.dqb_bsoftlimit % 2 ?
			 (long) (quota.dqb_bsoftlimit / 2 + 1) : (long) (quota.dqb_bsoftlimit / 2));
#  else /* !(defined(QUOTA_BLOCKS) || defined(HAS_NO_QUOTACTL)	) */ 
		snprintf(outptr, outlen, "%ld", (long) quota.dqb_bsoftlimit);
#  endif /* !(defined(QUOTA_BLOCKS) || defined(HAS_NO_QUOTACTL)	) */ 
		break;

	    case 'Q':
		if (pw == NULL) {
		    strlcpy(outptr, "[unknown]", outlen);
		    break;
		}
/* more recent versions of linux have a different name for curblocks in the quota structure 
 * -- Chris Butler <chrisb@debian.org>  2006-03-23
 */
#if defined(_LINUX_QUOTA_VERSION) && (_LINUX_QUOTA_VERSION >= 2)
#define dqb_curblocks dqb_curspace
#endif
#  if defined(QUOTA_BLOCKS) || defined(HAS_NO_QUOTACTL)	
		/* 1024-blocks instead of 512-blocks */
		snprintf(outptr, outlen, "%ld", quota.dqb_curblocks % 2 ?
			 (long) (quota.dqb_curblocks / 2 + 1) : (long) (quota.dqb_curblocks / 2));
#  else /* !(defined(QUOTA_BLOCKS) || defined(HAS_NO_QUOTACTL)	) */ 
		snprintf(outptr, outlen, "%ld", quota.dqb_curblocks);
#  endif /* !(defined(QUOTA_BLOCKS) || defined(HAS_NO_QUOTACTL)	) */ 
		break;

	    case 'I':
		if (pw == NULL) {
		    strlcpy(outptr, "[unknown]", outlen);
		    break;
		}
#  if defined(QUOTA_INODE)
		snprintf(outptr, outlen, "%d", quota.dqb_ihardlimit);
#  else /* !(defined(QUOTA_INODE)) */ 
		snprintf(outptr, outlen, "%ld", (long) quota.dqb_fhardlimit);
#  endif /* !(defined(QUOTA_INODE)) */ 
		break;

	    case 'i':
		if (pw == NULL) {
		    strlcpy(outptr, "[unknown]", outlen);
		    break;
		}
#  if defined(QUOTA_INODE)
		snprintf(outptr, outlen, "%d", quota.dqb_isoftlimit);
#  else /* !(defined(QUOTA_INODE)) */ 
		snprintf(outptr, outlen, "%ld", (long) quota.dqb_fsoftlimit);
#  endif /* !(defined(QUOTA_INODE)) */ 
		break;

	    case 'q':
		if (pw == NULL) {
		    strlcpy(outptr, "[unknown]", outlen);
		    break;
		}
#  if defined(QUOTA_INODE)
		snprintf(outptr, outlen, "%d", quota.dqb_curinodes);
#  else /* !(defined(QUOTA_INODE)) */ 
		snprintf(outptr, outlen, "%ld", (long) quota.dqb_curfiles);
#  endif /* !(defined(QUOTA_INODE)) */ 
		break;

	    case 'H':
		if (pw == NULL) {
		    strlcpy(outptr, "[unknown]", outlen);
		    break;
		}
		time_quota(quota.dqb_curblocks, quota.dqb_bsoftlimit,
#  if defined(QUOTA_INODE)
			   quota.dqb_btime, timeleft);
#  else /* !(defined(QUOTA_INODE)) */ 
			   quota.dqb_btimelimit, timeleft);
#  endif /* !(defined(QUOTA_INODE)) */ 
		if (strcmp(timeleft, "-"))	
		    strlcpy(outptr, timeleft, outlen);
		else
		    strlcpy(outptr, "   -   ", outlen);
		break;

	    case 'h':
		if (pw == NULL) {
		    strlcpy(outptr, "[unknown]", outlen);
		    break;
		}
#  if defined(QUOTA_INODE)
		time_quota(quota.dqb_curinodes, quota.dqb_isoftlimit,
			   quota.dqb_itime, timeleft);
#  else /* !(defined(QUOTA_INODE)) */ 
		time_quota(quota.dqb_curfiles, quota.dqb_fsoftlimit,
			   quota.dqb_ftimelimit, timeleft);
#  endif /* !(defined(QUOTA_INODE)) */ 
		if (strcmp(timeleft, "-"))	
		    strlcpy(outptr, timeleft, outlen);
		else
		    strlcpy(outptr, "   -   ", outlen);
		break;
#endif /* defined(QUOTA) */ 

	    case '%':
		*outptr++ = '%';
		outlen -= 1;
		*outptr = '\0';
		break;

#if defined(TRANSFER_COUNT)
#  if defined(TRANSFER_LIMIT)
#    if defined(RATIO)
	    case 'x':
		switch (*++inptr) {
		case 'u':	/* upload bytes */
		    snprintf(outptr, outlen,"%" L_FORMAT, TRUNC_KB(data_count_in));
		    break;
		case 'd':	/* download bytes */
		    snprintf(outptr, outlen,"%" L_FORMAT, TRUNC_KB(data_count_out));
		    break;
		case 'R':	/* rate 1:n */
		    if (upload_download_rate > 0) {
			snprintf(outptr,outlen,"%d", upload_download_rate);
		    }
		    else {
			strlcpy(outptr,"free", outlen);
		    }
		    break;
		case 'c':	/* credit bytes */
		    if (upload_download_rate > 0) {
			off_t credit = (data_count_in * upload_download_rate) - (data_count_out - total_free_dl);
			snprintf(outptr, outlen, "%" L_FORMAT, TRUNC_KB(credit));
		    }
		    else {
			strlcpy(outptr,"unlimited",outlen);
		    }
		    break;
		case 'T':	/* time limit (minutes) */
		    if (limit_time > 0) {
			snprintf(outptr, outlen,"%" T_FORMAT, limit_time);
		    }
		    else {
			strlcpy(outptr,"unlimited", outlen);
		    }
		    break;
		case 'E':	/* elapsed time from loggedin (minutes) */
		    snprintf(outptr,outlen,"%" T_FORMAT, (time(NULL)-login_time)/60);
		    break;
		case 'L':	/* times left until force logout (minutes) */
		    if (limit_time > 0) {
			snprintf(outptr,outlen,"%" T_FORMAT, limit_time-(time(NULL)-login_time)/60);
		    }
		    else {
			strlcpy(outptr,"unlimited",outlen);
		    }
		    break;
		case 'U':	/* upload limit */
		    if (data_limit_raw_in > 0) {
			snprintf(outptr,outlen,"%" L_FORMAT, TRUNC_KB(data_limit_raw_in));
		    }
		    else if (data_limit_data_in > 0) {
			snprintf(outptr,outlen,"%" L_FORMAT, TRUNC_KB(data_limit_data_in));
		    }
		    else if (data_limit_raw_total > 0) {
			snprintf(outptr,outlen,"%" L_FORMAT, TRUNC_KB(data_limit_raw_total));
		    }
		    else if (data_limit_data_total > 0) {
			snprintf(outptr,outlen,"%" L_FORMAT, TRUNC_KB(data_limit_data_total));
		    }
		    else {
			strlcpy(outptr, "unlimited", outlen);
		    }
		    break;
		case 'D':	/* download limit */
		    if (data_limit_raw_out > 0) {
			snprintf(outptr,outlen,"%" L_FORMAT, TRUNC_KB(data_limit_raw_out));
		    }
		    else if (data_limit_data_out > 0) {
			snprintf(outptr,outlen,"%" L_FORMAT, TRUNC_KB(data_limit_data_out));
		    }
		    else if (data_limit_raw_total > 0) {
			snprintf(outptr,outlen,"%" L_FORMAT, TRUNC_KB(data_limit_raw_total));
		    }
		    else if (data_limit_data_total > 0) {
			snprintf(outptr,outlen,"%" L_FORMAT, TRUNC_KB(data_limit_data_total));
		    }
		    else {
			strlcpy(outptr, "unlimited", outlen);
		    }
		    break;
		default:
		    strlcpy(outptr,"%??",outlen);
		    break;
		}
		break;
#    endif /* defined(RATIO) */ 
#  endif /* defined(TRANSFER_LIMIT) */ 
#endif /* defined(TRANSFER_COUNT) */ 

		/* File transfer logging (xferlog) */
		case 'X':
		    if (xferdone) {  /* only if a transfer has just occurred */
			switch (*++inptr) {
			case 't':
			    snprintf(outptr, outlen, "%d", xfervalues.transfer_time);
			    break;
			case 's':
			    snprintf(outptr, outlen, "%" L_FORMAT, xfervalues.filesize);
			    break;
			case 'n':
			    snprintf(outptr, outlen, "%" L_FORMAT, xfervalues.transfer_bytes);
			    break;
			case 'P': /* absolute pathname */
			    /* FALLTHROUGH */
			case 'p': /* chroot-relative pathname */
			{
			    char namebuf[MAXPATHLEN];
			    int loop;

			    if (*inptr == 'P')
				wu_realpath(xfervalues.filename, namebuf, chroot_path);
			    else
				fb_realpath(xfervalues.filename, namebuf);
			    for (loop = 0; namebuf[loop]; loop++) {
				if (isspace(namebuf[loop]) || iscntrl(namebuf[loop]))
				    namebuf[loop] = '_';
			    }
			    snprintf(outptr, outlen, "%s", namebuf);
			    break;
			}
			case 'y':
			    snprintf(outptr, outlen, "%c", xfervalues.transfer_type);
			    break;
			case 'f':
			    snprintf(outptr, outlen, "%s", xfervalues.special_action);
			    break;
			case 'd':
			    snprintf(outptr, outlen, "%c", xfervalues.transfer_direction);
			    break;
			case 'm':
			    snprintf(outptr, outlen, "%c", xfervalues.access_mode);
			    break;
			case 'a':
			    snprintf(outptr, outlen, "%d", xfervalues.auth);
			    break;
			case 'r':
			    snprintf(outptr, outlen, "%" L_FORMAT, xfervalues.restart_offset);
			    break;
			case 'c':
			    snprintf(outptr, outlen, "%c", xfervalues.completion);
			    break;
			default:
			    snprintf(outptr, outlen, "%%X%c", *inptr);
			    break;
			}
		    }
		    else
			snprintf(outptr, outlen, "%%%c", *inptr);
		    break;

	    default:
		*outptr++ = '%';
		outlen -= 1;
		if (outlen > 1) {
		    *outptr++ = *inptr;
		    outlen -= 1;
		}
		*outptr = '\0';
		break;
	    }
	    outptr[outlen - 1] = '\0';
	    while (*outptr) {
		outptr++;
		outlen -= 1;
	    }
	}
	inptr++;
    }
    if (outlen > 0)
	*outptr = '\0';
}

/*************************************************************************/
/* FUNCTION  : cwd_beenhere                                              */
/* PURPOSE   : Return 1 if the user has already visited this directory   */
/*             via C_WD.                                                 */
/* ARGUMENTS : a power-of-two directory function code (README, MESSAGE)  */
/*************************************************************************/

int cwd_beenhere(int dircode)
{
    struct dirlist {
	struct dirlist *next;
	int dircode;
	char dirname[1];
    };

    static struct dirlist *head = NULL;
    struct dirlist *curptr;
    char cwd[MAXPATHLEN];
    size_t curlen;

    (void) fb_realpath(".", cwd);

    for (curptr = head; curptr != NULL; curptr = curptr->next) {
	if (strcmp(curptr->dirname, cwd) == 0) {
	    if (!(curptr->dircode & dircode)) {
		curptr->dircode |= dircode;
		return (0);
	    }
	    return (1);
	}
    }
  
    curlen = strlen(cwd) + 1 + sizeof(struct dirlist);
    curptr = (struct dirlist *) malloc(curlen);

    if (curptr != NULL) {
	curptr->next = head;
	head = curptr;
	curptr->dircode = dircode;
	strlcpy(curptr->dirname, cwd, curlen);
    }
    return (0);
}

/*************************************************************************/
/* FUNCTION  : show_banner                                               */
/* PURPOSE   : Display a banner on the user's terminal before login      */
/* ARGUMENTS : reply code to use                                         */
/*************************************************************************/

void show_banner(int msgcode)
{
    char *crptr, linebuf[1024], outbuf[1024];
    struct aclmember *entry = NULL;
    FILE *infile;

#if defined(VIRTUAL)
    extern int virtual_mode;
    extern int virtual_ftpaccess;
    extern char virtual_banner[];

    if (virtual_mode && !virtual_ftpaccess) {
	infile = fopen(virtual_banner, "r");
	if (infile) {
	    while (fgets(linebuf, sizeof(linebuf), infile) != NULL) {
		if ((crptr = strchr(linebuf, '\n')) != NULL)
		    *crptr = '\0';
		msg_massage(linebuf, outbuf, sizeof(outbuf));
		lreply(msgcode, "%s", outbuf);
	    }
	    fclose(infile);
#  if !defined(NO_SUCKING_NEWLINES)
	    lreply(msgcode, "");
#  endif /* !defined(NO_SUCKING_NEWLINES) */ 
	}
    }
    else {
#endif /* defined(VIRTUAL) */ 
	/* banner <path> */
	while (getaclentry("banner", &entry)) {
	    if (!ARG0)
		continue;
	    infile = fopen(ARG0, "r");
	    if (infile) {
		while (fgets(linebuf, sizeof(linebuf), infile) != NULL) {
		    if ((crptr = strchr(linebuf, '\n')) != NULL)
			*crptr = '\0';
		    msg_massage(linebuf, outbuf, sizeof(outbuf));
		    lreply(msgcode, "%s", outbuf);
		}
		fclose(infile);
#if !defined(NO_SUCKING_NEWLINES)
		lreply(msgcode, "");
#endif /* !defined(NO_SUCKING_NEWLINES) */ 
	    }
	}
#if defined(VIRTUAL)
    }
#endif /* defined(VIRTUAL) */ 
}
/*************************************************************************/
/* FUNCTION  : show_message                                              */
/* PURPOSE   : Display a message on the user's terminal if the current   */
/*             conditions are right                                      */
/* ARGUMENTS : reply code to use, LOG_IN|CMD                             */
/*************************************************************************/

void show_message(int msgcode, int mode)
{
    char *crptr, linebuf[1024], outbuf[1024], class[MAXPATHLEN], cwd[MAXPATHLEN];
    int show, which;
    struct aclmember *entry = NULL;
    FILE *infile;

    if (mode == C_WD && cwd_beenhere(1) != 0)
	return;

#if defined(HAVE_GETCWD)
    (void) getcwd(cwd, MAXPATHLEN - 1);
#else /* !(defined(HAVE_GETCWD)) */ 
    (void) getwd(cwd);
#endif /* !(defined(HAVE_GETCWD)) */ 
    (void) acl_getclass(class, sizeof(class));

    /* message <path> [<when> [<class>]] */
    while (getaclentry("message", &entry)) {
	if (!ARG0)
	    continue;
	show = 0;

	if (mode == LOG_IN && (!ARG1 || !strcasecmp(ARG1, "login"))) {
	    if (!ARG2)
		show++;
	    else {
		for (which = 2; (which < MAXARGS) && ARG[which]; which++)
		    if (strcasecmp(class, ARG[which]) == 0)
			show++;
	    }
	}
	if (mode == C_WD && ARG1 && !strncasecmp(ARG1, "cwd=", 4) &&
	    (!strcmp((ARG1) + 4, cwd) || *(ARG1 + 4) == '*' ||
	     !wu_fnmatch((ARG1) + 4, cwd, FNM_PATHNAME))) {
	    if (!ARG2)
		show++;
	    else {
		for (which = 2; (which < MAXARGS) && ARG[which]; which++)
		    if (strcasecmp(class, ARG[which]) == 0)
			show++;
	    }
	}
	if (show && (int) strlen(ARG0) > 0) {
	    infile = fopen(ARG0, "r");
	    if (infile) {
		while (fgets(linebuf, sizeof(linebuf), infile) != NULL) {
		    if ((crptr = strchr(linebuf, '\n')) != NULL)
			*crptr = '\0';
		    msg_massage(linebuf, outbuf, sizeof(outbuf));
		    lreply(msgcode, "%s", outbuf);
		}
		fclose(infile);
#if !defined(NO_SUCKING_NEWLINES)
		lreply(msgcode, "");
#endif /* !defined(NO_SUCKING_NEWLINES) */ 
	    }
	}
    }
}

/*************************************************************************/
/* FUNCTION  : show_readme                                               */
/* PURPOSE   : Display a message about a README file to the user if the  */
/*             current conditions are right                              */
/* ARGUMENTS : pointer to ACL buffer, reply code, LOG_IN|C_WD            */
/*************************************************************************/

void show_readme(int code, int mode)
{
    char **filelist, **sfilelist, class[MAXPATHLEN], cwd[MAXPATHLEN];
    int show, which, days;
    time_t clock;

    struct stat buf;
    struct tm *tp;
    struct aclmember *entry = NULL;

    if (cwd_beenhere(2) != 0)
	return;

#if defined(HAVE_GETCWD)
    (void) getcwd(cwd, MAXPATHLEN - 1);
#else /* !(defined(HAVE_GETCWD)) */ 
    (void) getwd(cwd);
#endif /* !(defined(HAVE_GETCWD)) */ 
    (void) acl_getclass(class, sizeof(class));

    /* readme  <path> {<when>} */
    while (getaclentry("readme", &entry)) {
	if (!ARG0)
	    continue;
	show = 0;

	if (mode == LOG_IN && (!ARG1 || !strcasecmp(ARG1, "login"))) {
	    if (!ARG2)
		show++;
	    else {
		for (which = 2; (which < MAXARGS) && ARG[which]; which++)
		    if (strcasecmp(class, ARG[which]) == 0)
			show++;
	    }	
	}
	if (mode == C_WD && ARG1 && !strncasecmp(ARG1, "cwd=", 4)
	    && (!strcmp((ARG1) + 4, cwd) || *(ARG1 + 4) == '*' ||
		!wu_fnmatch((ARG1) + 4, cwd, FNM_PATHNAME))) {
	    if (!ARG2)
		show++;
	    else {
		for (which = 2; (which < MAXARGS) && ARG[which]; which++)
		    if (strcasecmp(class, ARG[which]) == 0)
			show++;
	    }
	}
	if (show) {
	    globerr = NULL;
	    filelist = ftpglob(ARG0);
	    sfilelist = filelist;	/* save to free later */
	    if (!globerr) {
		while (filelist && *filelist) {
		    errno = 0;
		    if (!stat(*filelist, &buf) &&
			(buf.st_mode & S_IFMT) == S_IFREG) {
			lreply(code, "Please read the file %s", *filelist);
			(void) time(&clock);
			tp = localtime(&clock);
			days = 365 * tp->tm_year + tp->tm_yday;
			tp = localtime((time_t *) & buf.st_mtime);
			days -= 365 * tp->tm_year + tp->tm_yday;
/*
   if (days == 0) {
   lreply(code, "  it was last modified on %.24s - Today",
   ctime((time_t *)&buf.st_mtime));
   } else {
 */
			lreply(code,
			   "  it was last modified on %.24s - %d day%s ago",
			       ctime((time_t *) & buf.st_mtime), days, days == 1 ? "" : "s");
/*
   }
 */
		    }
		    filelist++;
		}
	    }
	    if (sfilelist) {
		blkfree(sfilelist);
		free((char *) sfilelist);
	    }
	}
    }
}

/*************************************************************************/
/* FUNCTION  : deny_badxfertype                                          */
/* PURPOSE   : If user is in ASCII transfer mode and tries to retrieve a */
/*             binary file, abort transfer and display appropriate error */
/* ARGUMENTS : message code to use for denial, path of file to check for */
/*             binary contents or NULL to assume binary file             */
/*************************************************************************/

int deny_badasciixfer(int msgcode, char *filepath)
{

    if (type == TYPE_A && !*filepath) {
	reply(msgcode, "This is a BINARY file, using ASCII mode to transfer will corrupt it.");
	return (1);
    }
    /* The hooks are here to prevent transfers of actual binary files, not
     * just TAR or COMPRESS mode files... */
    return (0);
}

/*************************************************************************/
/* FUNCTION  : is_shutdown                                               */
/* PURPOSE   : Check to see if the server is shutting down, if it is     */
/*             arrange for the shutdown message to be sent in the next   */
/*             reply to the user                                         */
/* ARGUMENTS : whether to arrange for a shutdown message to be sent, new */
/*             or existing connection                                    */
/* RETURNS   : 1 if shutting down, 0 if not                              */
/*************************************************************************/

int is_shutdown(int quiet, int new)
{
    static struct tm tmbuf;
    static struct stat s_last;
    static time_t last = 0, shut, deny, disc;
    static int valid;
    static char text[2048];
    struct stat s_cur;

    extern char *autospout, Shutdown[];

    FILE *fp;

    int deny_tmp, disc_tmp;

    int deny_off, disc_off;

    time_t curtime = time(NULL);

    char buf[1024], linebuf[1024];

    if (Shutdown[0] == '\0' || stat(Shutdown, &s_cur))
	return (0);

    if (s_last.st_mtime != s_cur.st_mtime) {
	valid = 0;

	fp = fopen(Shutdown, "r");
	if (fp == NULL)
	    return (0);
	s_last = s_cur;
	fgets(buf, sizeof(buf), fp);
	if (sscanf(buf, "%d %d %d %d %d %d %d", &tmbuf.tm_year, &tmbuf.tm_mon,
	&tmbuf.tm_mday, &tmbuf.tm_hour, &tmbuf.tm_min, &deny_tmp, &disc_tmp) != 7) {
	    (void) fclose(fp);
	    return (0);
	}
	deny = deny_tmp;
	disc = disc_tmp;
	valid = 1;
	deny_off = 3600 * (deny / 100) + 60 * (deny % 100);
	disc_off = 3600 * (disc / 100) + 60 * (disc % 100);

	tmbuf.tm_year -= 1900;
	tmbuf.tm_isdst = -1;
	shut = mktime(&tmbuf);
	strlcpy(shuttime, ctime(&shut), sizeof(shuttime));

	disc = shut - disc_off;
	strlcpy(disctime, ctime(&disc), sizeof(disctime));

	deny = shut - deny_off;
	strlcpy(denytime, ctime(&deny), sizeof(denytime));

	text[0] = '\0';

        while (fgets(buf, sizeof(buf), fp) != NULL) {
            msg_massage(buf, linebuf, sizeof(linebuf));
            if (strlcat(text, linebuf, sizeof(text)) >= sizeof(text))
              break;
        }

	(void) fclose(fp);
    }
    if (!valid)
	return (0);

    /* if last == 0, then is_shutdown() only called with quiet == 1 so far */
    if (last == 0 && !quiet) {
	autospout = text;	/* warn them for the first time */
	autospout_free = 0;
	last = curtime;
    }
    /* if a new connection and past deny time, tell caller to drop 'em */
    if (new && curtime > deny)
	return (1);

    /* if past disconnect time, tell caller to drop 'em */
    if (curtime > disc)
	return (1);

    /* if less than 60 seconds to disconnection, warn 'em continuously */
    if (curtime > (disc - 60) && !quiet) {
	autospout = text;
	autospout_free = 0;
	last = curtime;
    }
    /* if less than 15 minutes to disconnection, warn 'em every 5 mins */
    if (curtime > (disc - 60 * 15)) {
	if ((curtime - last) > (60 * 5) && !quiet) {
	    autospout = text;
	    autospout_free = 0;
	    last = curtime;
	}
    }
    /* if less than 24 hours to disconnection, warn 'em every 30 mins */
    if (curtime < (disc - 24 * 60 * 60) && !quiet) {
	if ((curtime - last) > (60 * 30)) {
	    autospout = text;
	    autospout_free = 0;
	    last = curtime;
	}
    }
    /* if more than 24 hours to disconnection, warn 'em every 60 mins */
    if (curtime > (disc - 24 * 60 * 60) && !quiet) {
	if ((curtime - last) >= (24 * 60 * 60)) {
	    autospout = text;
	    autospout_free = 0;
	    last = curtime;
	}
    }
    return (0);
}

#if defined(SITE_NEWER)
void newer(char *date, char *path, int showlots)
{
    struct tm tm;

    if (sscanf(date, "%04d%02d%02d%02d%02d%02d",
	       &tm.tm_year, &tm.tm_mon, &tm.tm_mday,
	       &tm.tm_hour, &tm.tm_min, &tm.tm_sec) == 6) {

	tm.tm_year -= 1900;
	tm.tm_mon--;
	tm.tm_isdst = -1;
	newer_time = mktime(&tm);
	dout = dataconn("file list", (off_t) - 1, "w");

	if (dout != NULL) {
	    /* As ftw allocates storage it needs a chance to cleanup, setting
	     * ftwflag prevents myoob from calling longjmp, incrementing
	     * ftwflag instead which causes check_newer to return non-zero
	     * which makes ftw return. */
	    ftwflag = 1;
	    transflag++;
	    show_fullinfo = showlots;
#  if defined(HAVE_FTW)
	    ftw(path, check_newer, -1);
#  else /* !(defined(HAVE_FTW)) */ 
	    treewalk(path, check_newer, -1, NULL);
#  endif /* !(defined(HAVE_FTW)) */ 

	    /* don't send a reply if myoob has already replied */
	    if (ftwflag == 1) {
		if (ferror(dout) != 0)
		    perror_reply(550, "Data connection");
		else
		    reply(226, "Transfer complete.");
	    }

	    (void) fclose(dout);
	    data = -1;
	    pdata = -1;
	    transflag = 0;
	    ftwflag = 0;
	}
    }
    else
	reply(501, "Bad DATE format");
}
#endif /* defined(SITE_NEWER) */ 

int type_match(char *typelist)
{
    char *start, *p;
    int len;

    if (typelist == NULL)
	return (0);

    for (p = start = typelist; *start != '\0'; start = p) {
	while (*p != '\0' && *p != ',')
	    p++;
	len = p - start;
	if (*p != '\0')
	    p++;
	if (len == 9 && anonymous && strncasecmp(start, "anonymous", 9) == 0)
	    return (1);
	if (len == 5 && guest && strncasecmp(start, "guest", 5) == 0)
	    return (1);
	if (len == 4 && !guest && !anonymous &&
	    strncasecmp(start, "real", 4) == 0)
	    return (1);

	if (len > 6 && strncasecmp(start, "class=", 6) == 0) {
	    char class[1024];

	    if ((acl_getclass(class, sizeof(class)) == 1) && (strlen(class) == len - 6) &&
		(strncasecmp(start + 6, class, len - 6) == 0))
		return (1);
	}
    }
    return (0);
}

int path_compare(char *p1, char *p2)
{
    if ((strcmp(p1, "*") == 0) || (wu_fnmatch(p1, p2, FNM_PATHNAME) == 0))	/* 0 means they matched */
	return (strlen(p1));
    else
	return (-2);
}

void expand_id(void)
{
    char class[1024];
    struct aclmember *entry = NULL;

    (void) acl_getclass(class, sizeof(class));
    while (getaclentry("upload", &entry)) {
	char *q;
	int i = 0;
	int options = 1;
	int classfound = 0;
	int classmatched = 0;
	while (options
	       && (i < MAXARGS)
	       && ((q = entry->arg[i]) != (char *) NULL)
	       && (q[0] != '\0')) {
	    if (strcasecmp(q, "absolute") == 0)
		i++;
	    else if (strcasecmp(q, "relative") == 0)
		i++;
	    else if (strncasecmp(q, "class=", 6) == 0) {
		i++;
		classfound = 1;
		if (strcasecmp(q + 6, class) == 0)
		    classmatched = 1;
	    }
	    else if (strcmp(q, "-") == 0) {
		i++;
		options = 0;
	    }
	    else
		options = 0;
	}
	if (!classfound || classmatched) {
	    char buf[BUFSIZ];
            size_t blen;
	    /*
	     * File UID
	     */
	    if (((i + 3) < MAXARGS)
		&& ((q = entry->arg[i + 3]) != (char *) NULL)
		&& (q[0] != '\0')
		&& (strcmp(q, "*") != 0)) {
		if (q[0] == '%')
		    snprintf(buf, sizeof(buf), "%s", q + 1);
		else {
		    struct passwd *pwent = getpwnam(q);
		    if (pwent)
			snprintf(buf, sizeof(buf), "%" PW_UID_FORMAT, pwent->pw_uid);
		    else
			snprintf(buf, sizeof(buf), "%d", 0);
		}
		blen = strlen(buf) + 1;
		entry->arg[i + 3] = (char *) malloc(blen);
		if (entry->arg[i + 3] == NULL) {
		    syslog(LOG_ERR, "calloc error in expand_id");
		    dologout(1);
		}
		strlcpy(entry->arg[i + 3], buf, blen);
	    }
	    /*
	     * File GID
	     */
	    if (((i + 4) < MAXARGS)
		&& ((q = entry->arg[i + 4]) != (char *) NULL)
		&& (q[0] != '\0')
		&& (strcmp(q, "*") != 0)) {
		if (q[0] == '%')
		    snprintf(buf, sizeof(buf), "%s", q + 1);
		else {
		    struct group *grent = getgrnam(q);
		    if (grent)
			snprintf(buf, sizeof(buf), "%" GR_GID_FORMAT, grent->gr_gid);
		    else
			snprintf(buf, sizeof(buf), "%d", 0);
		    endgrent();
		}
		blen = strlen(buf) + 1;
		entry->arg[i + 4] = (char *) malloc(blen);
		if (entry->arg[i + 4] == NULL) {
		    syslog(LOG_ERR, "calloc error in expand_id");
		    dologout(1);
		}
		strlcpy(entry->arg[i + 4], buf, blen);
	    }
	    /*
	     * Directory UID
	     */
	    if (((i + 8) < MAXARGS)
		&& ((q = entry->arg[i + 8]) != (char *) NULL)
		&& (q[0] != '\0')
		&& (strcmp(q, "*") != 0)) {
		if (q[0] == '%')
		    snprintf(buf, sizeof(buf), "%s", q + 1);
		else {
		    struct passwd *pwent = getpwnam(q);
		    if (pwent)
			snprintf(buf, sizeof(buf), "%" PW_UID_FORMAT, pwent->pw_uid);
		    else
			snprintf(buf, sizeof(buf), "%d", 0);
		}
		blen = strlen(buf) + 1;
		entry->arg[i + 8] = (char *) malloc(blen);
		if (entry->arg[i + 8] == NULL) {
		    syslog(LOG_ERR, "calloc error in expand_id");
		    dologout(1);
		}
		strlcpy(entry->arg[i + 8], buf, blen);
	    }
	    /*
	     * Directory GID
	     */
	    if (((i + 9) < MAXARGS)
		&& ((q = entry->arg[i + 9]) != (char *) NULL)
		&& (q[0] != '\0')
		&& (strcmp(q, "*") != 0)) {
		if (q[0] == '%')
		    snprintf(buf, sizeof(buf), "%s", q + 1);
		else {
		    struct group *grent = getgrnam(q);
		    if (grent)
			snprintf(buf, sizeof(buf), "%" GR_GID_FORMAT, grent->gr_gid);
		    else
			snprintf(buf, sizeof(buf), "%d", 0);
		    endgrent();
		}
		blen = strlen(buf) + 1;
		entry->arg[i + 9] = (char *) malloc(blen);
		if (entry->arg[i + 9] == NULL) {
		    syslog(LOG_ERR, "calloc error in expand_id");
		    dologout(1);
		}
		strlcpy(entry->arg[i + 9], buf, blen);
	    }
	}
    }
}

int fn_check(char *name)
{
    /* check to see if this is a valid file name... path-filter <type>
     * <message_file> <allowed_charset> <disallowed> */

    struct aclmember *entry = NULL;
    int j;
    char *path;
#if ! defined(HAVE_REGEXEC)
    char *sp;
#endif /* ! defined(HAVE_REGEXEC) */ 

#if defined(M_UNIX)
#  if defined(HAVE_REGEX)
    char *regp;
#  endif /* defined(HAVE_REGEX) */ 
#endif /* defined(M_UNIX) */ 

#if defined(HAVE_REGEXEC)
    regex_t regexbuf;
    regmatch_t regmatchbuf;
    int rval;
    char errbuf[BUFSIZ];
#endif /* defined(HAVE_REGEXEC) */ 

#if defined(LINUX)
    re_syntax_options = RE_SYNTAX_POSIX_EXTENDED;
#endif /* defined(LINUX) */ 

    while (getaclentry("path-filter", &entry)) {
	if (!ARG0)
	    continue;
	if (type_match(ARG0) && ARG1 && ARG2) {

	    /*
	     * check *only* the basename
	     */

	    if ((path = strrchr(name, '/')))
		++path;
	    else
		path = name;

	    /* is it in the allowed character set? */
#if defined(HAVE_REGEXEC)
	    if ((rval = regcomp(&regexbuf, ARG2, REG_EXTENDED)) != 0) {
		errbuf[0] = '\0';
		regerror(rval, &regexbuf, errbuf, sizeof(errbuf));
		syslog(LOG_ERR, "path-filter allowed regular expression error: %s: %s", errbuf, ARG2);
#  elif defined(HAVE_REGEX)
	    if ((sp = regcmp(ARG2, (char *) 0)) == NULL) {
		syslog(LOG_ERR, "path-filter allowed regular expression error: %s", ARG2);
#else /* !(defined(HAVE_REGEXEC)) */ 
	    if ((sp = re_comp(ARG2)) != NULL) {
		syslog(LOG_ERR, "path-filter allowed regular expression error: %s: %s", sp, ARG2);
#endif /* !(defined(HAVE_REGEXEC)) */ 
		reply(550, "%s: Permission denied on server. (Filename (accept) regular expression error)", name);
		return (0);
	    }
#if defined(HAVE_REGEXEC)
	    rval = regexec(&regexbuf, path, 1, &regmatchbuf, 0);
	    regfree(&regexbuf);
	    if (rval != 0) {
#  elif defined(HAVE_REGEX)
#  if defined(M_UNIX)
	    regp = regex(sp, path);
	    free(sp);
	    if (regp == NULL) {
#  else /* !(defined(M_UNIX)) */ 
	    if ((regex(sp, path)) == NULL) {
#  endif /* !(defined(M_UNIX)) */ 
#else /* !(defined(HAVE_REGEXEC)) */ 
	    if ((re_exec(path)) != 1) {
#endif /* !(defined(HAVE_REGEXEC)) */ 
		pr_mesg(550, ARG1);
		reply(550, "%s: Permission denied on server. (Filename (accept))", name);
		return (0);
	    }
	    /* is it in any of the disallowed regexps */

	    for (j = 3; j < MAXARGS; ++j) {
		/* ARGj == entry->arg[j] */
		if (entry->arg[j]) {
#if defined(HAVE_REGEXEC)
		    if ((rval = regcomp(&regexbuf, entry->arg[j], REG_EXTENDED)) != 0) {
			errbuf[0] = '\0';
			regerror(rval, &regexbuf, errbuf, sizeof(errbuf));
			syslog(LOG_ERR, "path-filter disallowed regular expression error: %s: %s", errbuf, entry->arg[j]);
#  elif defined(HAVE_REGEX)
		    if ((sp = regcmp(entry->arg[j], (char *) 0)) == NULL) {
			syslog(LOG_ERR, "path-filter disallowed regular expression error: %s", entry->arg[j]);
#else /* !(defined(HAVE_REGEXEC)) */ 
		    if ((sp = re_comp(entry->arg[j])) != NULL) {
			syslog(LOG_ERR, "path-filter disallowed regular expression error: %s: %s", sp, entry->arg[j]);
#endif /* !(defined(HAVE_REGEXEC)) */ 
			reply(550, "%s: Permission denied on server. (Filename (deny) regular expression error)", name);
			return (0);
		    }
#if defined(HAVE_REGEXEC)
		    rval = regexec(&regexbuf, path, 1, &regmatchbuf, 0);
		    regfree(&regexbuf);
		    if (rval == 0) {
#  elif defined(HAVE_REGEX)
#  if defined(M_UNIX)
		    regp = regex(sp, path);
		    free(sp);
		    if (regp != NULL) {
#  else /* !(defined(M_UNIX)) */ 
		    if ((regex(sp, path)) != NULL) {
#  endif /* !(defined(M_UNIX)) */ 
#else /* !(defined(HAVE_REGEXEC)) */ 
		    if ((re_exec(path)) == 1) {
#endif /* !(defined(HAVE_REGEXEC)) */ 
			pr_mesg(550, ARG1);
			reply(550, "%s: Permission denied on server. (Filename (deny))", name);
			return (0);
		    }
		}
	    }
	}
    }
    return (1);
}

int dir_check(char *name, uid_t * uid, gid_t * gid, int *d_mode, int *valid, uid_t *duid, gid_t *dgid)
{
    struct aclmember *entry = NULL;
    int match_value = -1;
    char *ap2 = NULL;
    char *ap3 = NULL;
    char *ap4 = NULL;
    char *ap5 = NULL;
    char *ap6 = NULL;
    char *ap7 = NULL;
    char *ap8 = NULL;
    char *ap9 = NULL;
    char cwdir[MAXPATHLEN];
    char *pwdir;
    char abspwdir[MAXPATHLEN];
    char relpwdir[MAXPATHLEN];
    char path[MAXPATHLEN];
    char *sp;
    struct stat stbuf;
    int stat_result = -1;
    char class[1024];
    extern char *home;

    (void) acl_getclass(class, sizeof(class));

    *valid = 0;
    /* what's our current directory? */

    /* XXX We could use dynamic RAM to store this path, but I'd rather just bail
       out with an error. The rest of wu is so crufy that a long path might
       just blow up later */

    if (strlcpy(path, name, sizeof(path)) >= sizeof(path)) {
	perror_reply(550, "Path too long");
	return (-1);
    }

    sp = strrchr(path, '/');
    if (sp)
	*sp = '\0';
    else
	strlcpy(path, ".", sizeof(path));

    if ((fb_realpath(path, cwdir)) == NULL) {
	perror_reply(550, "Could not determine cwdir");
	return (-1);
    }

    if ((fb_realpath(home, relpwdir)) == NULL) {
	perror_reply(550, "Could not determine pwdir");
	return (-1);
    }

    if ((wu_realpath(home, abspwdir, chroot_path)) == NULL) {
	perror_reply(550, "Could not determine pwdir");
	return (-1);
    }

    while (getaclentry("upload", &entry)) {
	char *q;
	int i = 0;
	int options = 1;
	int classfound = 0;
	int classmatched = 0;
	pwdir = abspwdir;
	while (options
	       && (i < MAXARGS)
	       && ((q = entry->arg[i]) != (char *) NULL)
	       && (q[0] != '\0')) {
	    if (strcasecmp(q, "absolute") == 0) {
		i++;
		pwdir = abspwdir;
	    }
	    else if (strcasecmp(q, "relative") == 0) {
		i++;
		pwdir = relpwdir;
	    }
	    else if (strncasecmp(q, "class=", 6) == 0) {
		i++;
		classfound = 1;
		if (strcasecmp(q + 6, class) == 0)
		    classmatched = 1;
	    }
	    else if (strcmp(q, "-") == 0) {
		i++;
		options = 0;
	    }
	    else
		options = 0;
	}
	if (!classfound || classmatched) {
	    int j;
	    if (((i + 1) < MAXARGS)
		&& ((q = entry->arg[i]) != (char *) NULL)
		&& (q[0] != '\0')
		&& (0 < path_compare(q, pwdir))
		&& ((j = path_compare(entry->arg[i + 1], cwdir)) >= match_value)) {
		match_value = j;

		ap2 = NULL;
		if (((i + 2) < MAXARGS)
		    && ((q = entry->arg[i + 2]) != (char *) NULL)
		    && (q[0] != '\0'))
		    ap2 = q;

		ap3 = NULL;
		if (((i + 3) < MAXARGS)
		    && ((q = entry->arg[i + 3]) != (char *) NULL)
		    && (q[0] != '\0'))
		    ap3 = q;

		ap4 = NULL;
		if (((i + 4) < MAXARGS)
		    && ((q = entry->arg[i + 4]) != (char *) NULL)
		    && (q[0] != '\0'))
		    ap4 = q;

		ap5 = NULL;
		if (((i + 5) < MAXARGS)
		    && ((q = entry->arg[i + 5]) != (char *) NULL)
		    && (q[0] != '\0'))
		    ap5 = q;

		ap6 = NULL;
		if (((i + 6) < MAXARGS)
		    && ((q = entry->arg[i + 6]) != (char *) NULL)
		    && (q[0] != '\0'))
		    ap6 = q;

		ap7 = NULL;
		if (((i + 7) < MAXARGS)
		    && ((q = entry->arg[i + 7]) != (char *) NULL)
		    && (q[0] != '\0'))
		    ap7 = q;

		ap8 = NULL;
		if (((i + 8) < MAXARGS)
		    && ((q = entry->arg[i + 8]) != (char *) NULL)
		    && (q[0] != '\0'))
		    ap8 = q;

		ap9 = NULL;
		if (((i + 9) < MAXARGS)
		    && ((q = entry->arg[i + 9]) != (char *) NULL)
		    && (q[0] != '\0'))
		    ap9 = q;
	    }
	}
    }

    if (anonymous && (match_value < 0)) {
	reply(550, "%s: Permission denied on server. (Upload dirs)", name);
	return (0);
    }
    if ((ap2 && !strcasecmp(ap2, "no"))
	|| (ap3 && !strcasecmp(ap3, "nodirs"))
	|| (ap6 && !strcasecmp(ap6, "nodirs"))) {
	reply(550, "%s: Permission denied on server. (Upload dirs)", name);
	return (0);
    }
    if ((ap3 && *ap3 == '*') || (ap4 && *ap4 == '*') ||
	(ap8 && *ap8 == '*') || (ap9 && *ap9 == '*'))
	stat_result = stat(path, &stbuf);
    if (ap3) {
	if ((ap3[0] != '*') || (ap3[1] != '\0'))
	    *uid = atoi(ap3);	/* the uid  */
	else if (stat_result == 0)
	    *uid = stbuf.st_uid;
        else {
            reply(550, "%s: Permission denied on server. (Current dir)", name);
            return 0;
        }
    }
    if (ap4) {
	if ((ap4[0] != '*') || (ap4[1] != '\0'))
	    *gid = atoi(ap4);	/* the gid */
	else if (stat_result == 0)
	    *gid = stbuf.st_gid;
        else {
            reply(550, "%s: Permission denied on server. (Current dir)", name);
            return 0;
        }
    }
    if (ap8) {
	if ((ap8[0] != '*') || (ap8[1] != '\0'))
	    *duid = atoi(ap8);	/* the uid  */
	else if (stat_result == 0)
	    *duid = stbuf.st_uid;
        else {
            reply(550, "%s: Permission denied on server. (Current dir)", name);
            return 0;
        }
    }
    else
	*duid = *uid;
    if (ap9) {
	if ((ap9[0] != '*') || (ap9[1] != '\0'))
	    *dgid = atoi(ap9);	/* the gid */
	else if (stat_result == 0)
	    *dgid = stbuf.st_gid;
        else {
            reply(550, "%s: Permission denied on server. (Current dir)", name);
            return 0;
        }
    }
    else
	*dgid = *gid;
    if (ap7) {
	sscanf(ap7, "%o", d_mode);
	*valid = 1;
    }
    else if (ap5) {
	sscanf(ap5, "%o", d_mode);
	if (*d_mode & 0600)
	    *d_mode |= 0100;
	if (*d_mode & 0060)
	    *d_mode |= 0010;
	if (*d_mode & 0006)
	    *d_mode |= 0001;
	*valid = 1;
    }
    return (1);
}

int upl_check(char *name, uid_t * uid, gid_t * gid, int *f_mode, int *valid)
{
    int match_value = -1;
    char cwdir[MAXPATHLEN];
    char *pwdir;
    char abspwdir[MAXPATHLEN];
    char relpwdir[MAXPATHLEN];
    char path[MAXPATHLEN];
    char *sp;
    struct stat stbuf;
    int stat_result = -1;
    char *ap2 = NULL;
    char *ap3 = NULL;
    char *ap4 = NULL;
    char *ap5 = NULL;
    struct aclmember *entry = NULL;
    char class[1024];
    extern char *home;

    *valid = 0;
    (void) acl_getclass(class, sizeof(class));

    /* what's our current directory? */

    /* XXX We could use dynamic RAM to store this path, but I'd rather just bail
       out with an error. The rest of wu is so crufy that a long path might
       just blow up later */

    if (strlcpy(path, name, sizeof(path)) >= sizeof(path)) {
	perror_reply(553, "Path too long");
	return (-1);
    }

    sp = strrchr(path, '/');
    if (sp)
	*sp = '\0';
    else
	strlcpy(path, ".", sizeof(path));

    if ((fb_realpath(path, cwdir)) == NULL) {
	perror_reply(553, "Could not determine cwdir");
	return (-1);
    }

    if ((wu_realpath(home, abspwdir, chroot_path)) == NULL) {
	perror_reply(553, "Could not determine pwdir");
	return (-1);
    }

    if ((fb_realpath(home, relpwdir)) == NULL) {
	perror_reply(553, "Could not determine pwdir");
	return (-1);
    }

    /*
       *  we are doing a "best match"... ..so we keep track of what "match
       *  value" we have received so far...
     */
    while (getaclentry("upload", &entry)) {
	char *q;
	int i = 0;

	pwdir = match_class_user(entry->arg, &i, class, abspwdir, relpwdir);
	if (pwdir != NULL) {
	    int j;
	    if (((i + 1) < MAXARGS)
		&& ((q = entry->arg[i]) != (char *) NULL)
		&& (q[0] != '\0')
		&& (0 < path_compare(q, pwdir))
		&& ((j = path_compare(entry->arg[i + 1], cwdir)) >= match_value)) {
		match_value = j;

		ap2 = NULL;
		if (((i + 2) < MAXARGS)
		    && ((q = entry->arg[i + 2]) != (char *) NULL)
		    && (q[0] != '\0'))
		    ap2 = q;

		ap3 = NULL;
		if (((i + 3) < MAXARGS)
		    && ((q = entry->arg[i + 3]) != (char *) NULL)
		    && (q[0] != '\0'))
		    ap3 = q;

		ap4 = NULL;
		if (((i + 4) < MAXARGS)
		    && ((q = entry->arg[i + 4]) != (char *) NULL)
		    && (q[0] != '\0'))
		    ap4 = q;

		ap5 = NULL;
		if (((i + 5) < MAXARGS)
		    && ((q = entry->arg[i + 5]) != (char *) NULL)
		    && (q[0] != '\0'))
		    ap5 = q;
	    }
	}
    }

    if (ap3
	&& ((!strcasecmp("dirs", ap3))
	    || (!strcasecmp("nodirs", ap3))))
	ap3 = NULL;

    /*
       *  if we did get matches ... else don't do any of this stuff
     */
    if (match_value >= 0) {
	if (!strcasecmp(ap2, "yes")) {
	    if ((ap3 && *ap3 == '*') || (ap4 && *ap4 == '*'))
		stat_result = stat(path, &stbuf);
	    if (ap3) {
		if ((ap3[0] != '*') || (ap3[1] != '\0'))
		    *uid = atoi(ap3);	/* the uid  */
		else if (stat_result == 0)
		    *uid = stbuf.st_uid;
                else {
                    reply(553, "%s: Permission denied on server. (Current dir)", name);
                    return (-1);
                }
	    }
	    if (ap4) {
		if ((ap4[0] != '*') || (ap4[1] != '\0'))
		    *gid = atoi(ap4);	/* the gid  */
		else if (stat_result == 0)
		    *gid = stbuf.st_gid;
                else {
                    reply(553, "%s: Permission denied on server. (Current dir)", name);
                    return (-1);
                }
		*valid = 1;
	    }
	    if (ap5)
		sscanf(ap5, "%o", f_mode);	/* the mode */
	}
	else {
	    reply(553, "%s: Permission denied on server. (Upload)", name);
	    return (-1);
	}
    }
    else {
	/*
	   *  upload defaults to "permitted"
	 */
	/* Not if anonymous */
	if (anonymous) {
	    reply(553, "%s: Permission denied on server. (Upload)", name);
	    return (-1);
	}
	return (1);
    }

    return (match_value);
}

int del_check(char *name)
{
    int pdelete = (anonymous ? 0 : 1);
    struct aclmember *entry = NULL;

    while (getaclentry("delete", &entry)) {
	if (!ARG0)
	    continue;
	if (!ARG1) {
	    if (!anonymous && ((*ARG0 == 'n') || (*ARG0 == 'N')))
		pdelete = 0;
	}
	else if (type_match(ARG1)) {
	    if (anonymous) {
		if ((*ARG0 == 'y') || (*ARG0 == 'Y'))
		    pdelete = 1;
	    }
	    else if ((*ARG0 == 'n') || (*ARG0 == 'N'))
		pdelete = 0;	
	}
    }

/* H* fix: no deletion, period. You put a file here, I get to look at it. */
#if !defined(ENABLE_DELETE)
    pdelete = 0;
#endif /* !defined(ENABLE_DELETE) */ 

    if (!pdelete) {
	reply(553, "%s: Permission denied on server. (Delete)", name);
	return (0);
    }
    else {
	return (1);
    }
}

/* The following is from the Debian add-ons. */

#define lbasename(x) (strrchr(x,'/')?1+strrchr(x,'/'):x)

int regexmatch(char *name, char *rgexp)
{

#if defined(M_UNIX)
#  if defined(HAVE_REGEX)
    char *regp;
#  endif /* defined(HAVE_REGEX) */ 
#endif /* defined(M_UNIX) */ 

#if defined(HAVE_REGEXEC)
    regex_t regexbuf;
    regmatch_t regmatchbuf;
    int rval;
    char errbuf[BUFSIZ];
#else /* !(defined(HAVE_REGEXEC)) */ 
    char *sp;
#endif /* !(defined(HAVE_REGEXEC)) */ 

#if defined(HAVE_REGEXEC)
    if ((rval = regcomp(&regexbuf, rgexp, REG_EXTENDED)) != 0) {
	errbuf[0] = '\0';
	regerror(rval, &regexbuf, errbuf, sizeof(errbuf));
	syslog(LOG_ERR, "regular expression error: %s: %s", errbuf, rgexp);
#  elif defined(HAVE_REGEX)
    if ((sp = regcmp(rgexp, (char *) 0)) == NULL) {
	syslog(LOG_ERR, "regular expression error: %s", rgexp);
#else /* !(defined(HAVE_REGEXEC)) */ 
    if ((sp = re_comp(rgexp)) != NULL) {
	syslog(LOG_ERR, "regular expression error: %s: %s", sp, rgexp);
#endif /* !(defined(HAVE_REGEXEC)) */ 
	return (0);
    }

#if defined(HAVE_REGEXEC)
    rval = regexec(&regexbuf, name, 1, &regmatchbuf, 0);
    regfree(&regexbuf);
    if (rval != 0) {
#  elif defined(HAVE_REGEX)
#  if defined(M_UNIX)
    regp = regex(sp, name);
    free(sp);
    if (regp == NULL) {
#  else /* !(defined(M_UNIX)) */ 
    if ((regex(sp, name)) == NULL) {
#  endif /* !(defined(M_UNIX)) */ 
#else /* !(defined(HAVE_REGEXEC)) */ 
    if ((re_exec(name)) != 1) {
#endif /* !(defined(HAVE_REGEXEC)) */ 
	return (0);
    }
    return (1);
}

static int allow_retrieve(char *name)
{
    char realname[MAXPATHLEN];
    char localname[MAXPATHLEN];
    char *whichname;
    int i;
    struct aclmember *entry = NULL;
    char *p, *q;
    char class[1024];

    (void) acl_getclass(class, sizeof(class));
    if ((name == (char *) NULL)
	|| (*name == '\0'))
	return 0;
    fb_realpath(name, localname);
    wu_realpath(name, realname, chroot_path);
    while (getaclentry("allow-retrieve", &entry)) {
	whichname = match_class_user(entry->arg, &i, class, realname, localname);
	if (whichname != NULL) {
	    for (; (i < MAXARGS) && ((q = entry->arg[i]) != (char *) NULL) && (q[0] != '\0'); i++) {
		p = (q[0] == '/') ? whichname : lbasename(whichname);
		if (!wu_fnmatch(q, p, FNM_PATHNAME | FNM_LEADING_DIR)) {
		    return 1;
		}
	    }
	}
    }
    return 0;
}

int checknoretrieve(char *name)
{
    char realname[MAXPATHLEN];
    char localname[MAXPATHLEN];
    char *whichname;
    int i;
    struct aclmember *entry = NULL;
    char *p, *q;
    char class[1024];

    (void) acl_getclass(class, sizeof(class));
    if ((name == (char *) NULL)
	|| (*name == '\0'))
	return 0;
    fb_realpath(name, localname);
    wu_realpath(name, realname, chroot_path);
	
    while (getaclentry("noretrieve", &entry)) {
	whichname = match_class_user(entry->arg, &i, class, realname, localname);
	if (whichname != NULL) {
	    for (; (i < MAXARGS) && ((q = entry->arg[i]) != (char *) NULL) && (q[0] != '\0'); i++) {
		p = (q[0] == '/') ? whichname : lbasename(whichname);
		if (!wu_fnmatch(q, p, FNM_PATHNAME | FNM_LEADING_DIR)) {
		    if (!allow_retrieve(name)) {
			reply(550, "%s is marked unretrievable", localname);
			return 1;
		    }
		}
	    }
	}
    }
    return 0;
}

char *match_class_user(char *argv[], int *i, char *class, char *realname, char *localname)
{
    int classfound = 0;
    int classmatched = 0;
    char *q;
    int userfound = 0;
    int usermatched  = 0;
    char *whichname;

    whichname = realname;

    for (*i = 0;
	 (*i < MAXARGS)
	   && ((q = argv[*i]) != (char *) NULL)
	   && (q[0] != '\0');
	 (*i)++) {
	if (strcasecmp(q, "absolute") == 0) {
	    whichname = realname;
	}
	else if (strcasecmp(q, "relative") == 0) {
	    whichname = localname;
	}
	else if (strncasecmp(q, "class=", 6) == 0) {
	    classfound = 1;
	    if (strcasecmp(q + 6, class) == 0)
		classmatched = 1;
	}
	else if (strncasecmp(q, "user=", 5) == 0) {
	    userfound = 1;
	    if (strcasecmp(q + 5, the_user) == 0) {
		usermatched = 1;
	    }
	}
	else if (strcmp(q, "-") == 0) {
	    (*i)++;
	    break;
	}
	else {
	    break;
	}
    }
    if ((!classfound && !userfound) || classmatched || usermatched) {
	return(whichname);
    } else {
	return(NULL);
    }
}

#if defined(QUOTA)

#  if !defined(MNTMAXSTR)
#    define MNTMAXSTR 2048		/* And hope it's enough */
#  endif /* !defined(MNTMAXSTR) */ 

#  if defined(QUOTA_DEVICE)

int path_to_device(char *pathname, char *result)
{
    FILE *fp;
#    if defined(HAS_OLDSTYLE_GETMNTENT)
    struct mnttab static_mp;
    struct mnttab *mp = &static_mp;
#    else /* !(defined(HAS_OLDSTYLE_GETMNTENT)) */ 
    struct mntent *mp;
#    endif /* !(defined(HAS_OLDSTYLE_GETMNTENT)) */ 
    struct mount_ent {
	char mnt_fsname[MNTMAXSTR], mnt_dir[MNTMAXSTR];
	struct mount_ent *next;
    } mountent;
    struct mount_ent *current, *start, *new;
    char path[MAXPATHLEN], mnt_dir[MAXPATHLEN], *pos;
    int flag = 1;

    start = current = NULL;
#    if defined(HAS_OLDSTYLE_GETMNTENT)
    fp = fopen(MNTTAB, "r");
#    else /* !(defined(HAS_OLDSTYLE_GETMNTENT)) */ 
    fp = setmntent(MNTTAB, "r");
#    endif /* !(defined(HAS_OLDSTYLE_GETMNTENT)) */ 
    if (fp == NULL)
	return 0;
#    if defined(HAS_OLDSTYLE_GETMNTENT)
    while (getmntent(fp, &static_mp) == 0)
#    else /* !(defined(HAS_OLDSTYLE_GETMNTENT)) */ 
    while (mp = getmntent(fp))
#    endif /* !(defined(HAS_OLDSTYLE_GETMNTENT)) */ 
    {
	if (!(new = (struct mount_ent *) malloc(sizeof(mountent)))) {
	    perror("malloc");
	    flag = 0;
	    break;
	}

	if (!start)
	    start = current = new;
	else
	    current = current->next = new;

#    if defined(HAS_OLDSTYLE_GETMNTENT)
	strlcpy(current->mnt_fsname, mp->mnt_special, strlen(mp->mnt_special) + 1);
	strlcpy(current->mnt_dir, mp->mnt_mountp, strlen(mp->mnt_mountp) + 1);
#    else /* !(defined(HAS_OLDSTYLE_GETMNTENT)) */ 
	strlcpy(current->mnt_fsname, mp->mnt_fsname, strlen(mp->mnt_fsname) + 1);
	strlcpy(current->mnt_dir, mp->mnt_dir, strlen(mp->mnt_dir) + 1);
#    endif /* !(defined(HAS_OLDSTYLE_GETMNTENT)) */ 
    }
#    if defined(HAS_OLDSTYLE_GETMNTENT)
    fclose(fp);
#    else /* !(defined(HAS_OLDSTYLE_GETMNTENT)) */ 
    endmntent(fp);
#    endif /* !(defined(HAS_OLDSTYLE_GETMNTENT)) */ 

    /* Debian BugID 568235 - should fstab be zero-length */
    if (!current)
	return 0;

    current->next = NULL;

    wu_realpath(pathname, path, chroot_path);

    while (*path && flag) {
	current = start;
	while (current && flag) {
	    if (strcmp(current->mnt_dir, "swap")) {
		wu_realpath(current->mnt_dir, mnt_dir, chroot_path);
		if (!strcmp(mnt_dir, path)) {
		    flag = 0;
		    /* no support for remote quota yet */
		    if (!strchr(current->mnt_fsname, ':'))
			strlcpy(result, current->mnt_fsname, MNTMAXSTR);
		}
	    }
	    current = current->next;
	}
	if (!((pos = strrchr(path, '/')) - path) && strlen(path) > 1)
	    strlcpy(path, "/", sizeof(path));
	else
	    path[pos - path] = '\0';
    }
    while (current) {
	new = current->next;
	free(current);
	current = new;
    }
    return 1;
}
#  endif /* defined(QUOTA_DEVICE) */ 

void get_quota(char *fs, int uid)
{
    char mnt_fsname[MNTMAXSTR];
    uid_t userid = geteuid();    /* To be on the safe side */
#  if defined(HAS_NO_QUOTACTL)
    int dirfd;
    struct quotctl qp;
#  endif /* defined(HAS_NO_QUOTACTL) */ 

    /*
     * Getting file system quota information can take a noticeable amount
     * of time, so only get quota information for specified users.
     * quota-info <uid-range> [<uid-range> ...]
     */
    if (!uid_match("quota-info", uid))
	return;

#  if defined(HAS_NO_QUOTACTL)
    if (path_to_device(fs, mnt_fsname)) {
	delay_signaling();  /* we can't allow any signals while euid==0 */
	seteuid(0);
	dirfd = open(fs, O_RDONLY);
	seteuid(userid);
	enable_signaling(); /* we can allow signals once again */
	qp.op = Q_GETQUOTA;
	qp.uid = uid;
	qp.addr = (char *) &quota;
	if (ioctl(dirfd, Q_QUOTACTL, &qp) == -1) {
	    /* Don't complain if the user doesn't have a quota */
	    if (errno != ESRCH)
		syslog(LOG_ERR, "ioctl(Q_QUOTACTL): %m");
	}
	close(dirfd);
    }
#  else /* !(defined(HAS_NO_QUOTACTL)) */ 
#    if defined(QUOTA_DEVICE)

    if (path_to_device(fs, mnt_fsname)) {
	delay_signaling();  /* we can't allow any signals while euid==0 */
	seteuid(0);
#      if defined(QCMD)
	if (!quotactl(QCMD(Q_GETQUOTA, USRQUOTA), mnt_fsname, uid,
			 (char *) &quota))
		syslog(LOG_ERR, "quotactl: %m");
#      else /* !(defined(QCMD)) */ 
	if (!quotactl(Q_GETQUOTA, mnt_fsname, uid, (char *) &quota))
		syslog(LOG_ERR, "quotactl: %m");
#      endif /* !(defined(QCMD)) */ 
    }
#    else /* !(defined(QUOTA_DEVICE)) */ 
    delay_signaling();  /* we can't allow any signals while euid==0 */
    seteuid(0);
    if (!quotactl(fs, QCMD(Q_GETQUOTA, USRQUOTA), uid, (char *) &quota))
	syslog(LOG_ERR, "quotactl: %m");
#    endif /* !(defined(QUOTA_DEVICE)) */ 
    seteuid(userid);
    enable_signaling(); /* we can allow signals once again */
#  endif /* !(defined(HAS_NO_QUOTACTL)) */ 
}

char *time_quota(long curstate, long softlimit, long timelimit, char *timeleft)
{
    struct timeval tv;

    gettimeofday(&tv, NULL);
    if (softlimit && curstate >= softlimit) {
	if (timelimit == 0) {
	    strlcpy(timeleft, "NOT STARTED", TIMELEFTLEN);
	}
	else if (timelimit > tv.tv_sec) {
	    fmttime(timeleft, TIMELEFTLEN, timelimit - tv.tv_sec);
	}
	else {
	    strlcpy(timeleft, "EXPIRED", TIMELEFTLEN);
	}
    }
    else {
	strlcpy(timeleft, "-", TIMELEFTLEN);
    }
    return (timeleft);
}

void fmttime(char *buf, size_t buflen, register long time)
{
    int i;
    static struct {
	int c_secs;		/* conversion units in secs */
	char *c_str;		/* unit string */
    } cunits[] = {
	{
	    60 *60 * 24 * 28, "months"
	} ,
	{
	    60 *60 * 24 * 7, "weeks"
	} ,
	{
	    60 *60 * 24, "days"
	} ,
	{
	    60 *60, "hours"
	} ,
	{
	    60, "mins"
	} ,
	{
	    1, "secs"
	}
    };

    if (time <= 0) {
	strlcpy(buf, "EXPIRED", buflen);
	return;
    }
    for (i = 0; i < sizeof(cunits) / sizeof(cunits[0]); i++) {
	if (time >= cunits[i].c_secs)
	    break;
    }
    snprintf(buf, buflen, "%.1f %s", (double) time / cunits[i].c_secs, cunits[i].c_str);
}

#endif /* defined(QUOTA) */ 

#if defined(THROUGHPUT)

int file_compare(char *patterns, char *file)
{
    char buf[MAXPATHLEN+1];
    char *cp;
    char *cp2;
    int i;
    int matches = 0;

    strlcpy(buf, patterns, sizeof(buf) - 1);
    i = strlen(buf);
    buf[i++] = ',';
    buf[i++] = '\0';

    cp = buf;
    while ((cp2 = strchr(cp, ',')) != NULL) {
	*cp2++ = '\0';
	if (wu_fnmatch(cp, file, FNM_PATHNAME) == 0) {
	    matches = 1;
	    break;
	}
	cp = cp2;
    }
    return matches;
}

int remote_compare(char *patterns)
{
    char buf[MAXPATHLEN+1];
    char *cp;
    char *cp2;
    int i;
    int matches = 0;

    strlcpy(buf, patterns, sizeof(buf) - 1);

    i = strlen(buf);
    buf[i++] = ',';
    buf[i++] = '\0';

    cp = buf;
    while ((cp2 = strchr(cp, ',')) != NULL) {
	*cp2++ = '\0';
	if (hostmatch(cp, remoteaddr, remotehost)) {
	    matches = 1;
	    break;
	}
	cp = cp2;
    }
    return matches;
}

void throughput_calc(char *name, int *bps, double *bpsmult)
{
    int match_value = -1;
    char cwdir[MAXPATHLEN];
    char pwdir[MAXPATHLEN];
    char path[MAXPATHLEN];
    char file[MAXPATHLEN];
    char *ap3 = NULL, *ap4 = NULL;
    struct aclmember *entry = NULL;
    extern char *home;
    char *sp;
    int i;

    /* default is maximum throughput */
    *bps = -1;
    *bpsmult = 1.0;

    /* XXX We could use dynamic RAM to store this path, but I'd rather just bail
       out with an error. The rest of wu is so crufy that a long path might
       just blow up later */

    if (strlcpy(path, name, sizeof(path)) >= sizeof(path)) {
	return;
    }

    /* what's our current directory? */

    if ((sp = strrchr(path, '/')))
	*sp = '\0';
    else
	strlcpy(path, ".", sizeof(path));
    if ((sp = strrchr(name, '/')))
	strlcpy(file, sp + 1, sizeof(file));
    else
	strlcpy(file, name, sizeof(file));
    if ((fb_realpath(path, cwdir)) == NULL) {
	return;
    }

    wu_realpath(home, pwdir, chroot_path);

    /* find best matching entry */
    while (getaclentry("throughput", &entry)) {
	if (ARG0 && ARG1 && ARG2 && ARG3 && ARG4 && ARG5 != NULL)
	if ((0 < path_compare(ARG0, pwdir))
	    && ((i = path_compare(ARG1, cwdir)) >= match_value)
	    ) {
	    if (file_compare(ARG2, file)) {
		if (remote_compare(ARG5)) {
		    match_value = i;
		    ap3 = ARG3;
		    ap4 = ARG4;
		}
	    }
	}
    }

    /* if we did get matches */
    if (match_value >= 0) {
	if (strcasecmp(ap3, "oo") == 0)
	    *bps = -1;
	else
	    *bps = atoi(ap3);
	if (strcmp(ap4, "-") == 0)
	    *bpsmult = 1.0;
	else
	    *bpsmult = atof(ap4);
    }
    return;
}

void throughput_adjust(char *name)
{
    int match_value = -1;
    char pwdir[MAXPATHLEN];
    char cwdir[MAXPATHLEN];
    char path[MAXPATHLEN];
    char file[MAXPATHLEN];
    char buf[MAXPATHLEN];
    char *ap3 = NULL, *ap4 = NULL;
    char **pap = NULL;
    struct aclmember *entry = NULL;
    extern char *home;
    char *sp;
    int i;
    size_t tlen;

    /* XXX We could use dynamic RAM to store this path, but I'd rather just bail
       out with an error. The rest of wu is so crufy that a long path might
       just blow up later */

    if (strlcpy(path, name, sizeof(path)) >= sizeof(path)) {
	return;
    }

    /* what's our current directory? */
    
    if ((sp = strrchr(path, '/')))
	*sp = '\0';
    else
	strlcpy(path, ".", sizeof(path));
    if ((sp = strrchr(name, '/')))
	strlcpy(file, sp + 1, sizeof(file));
    else
	strlcpy(file, name, sizeof(file));
    if ((fb_realpath(path, cwdir)) == NULL) {
	return;
    }

    wu_realpath(home, pwdir, chroot_path);

    /* find best matching entry */
    while (getaclentry("throughput", &entry)) {
	if (ARG0 && ARG1 && ARG2 && ARG3 && ARG4 && ARG5 != NULL)
	if ((0 < path_compare(ARG0, pwdir))
	    && ((i = path_compare(ARG1, cwdir)) >= match_value)) {
	    if (file_compare(ARG2, file)) {
		if (remote_compare(ARG5)) {
		    match_value = i;
		    ap3 = ARG3;
		    pap = ARG;
		    ap4 = ARG4;
		}
	    }
	}
    }

    /* if we did get matches */
    if (match_value >= 0) {
	if (strcasecmp(ap3, "oo") != 0) {
	    if (strcmp(ap4, "-") != 0) {
		snprintf(buf, sizeof(buf), "%.0f", atoi(ap3) * atof(ap4));
		tlen = strlen(buf) + 1;
		pap[3] = (char *) malloc(tlen);
		if (pap[3] == NULL) {
		    syslog(LOG_ERR, "malloc error in throughput_adjust");
		    dologout(1);
		}
		/* Use ARG6 to keep track of malloced memory */
		if (pap[6])
		    free(pap[6]);
		pap[6] = pap[3];
		strlcpy(pap[3], buf, tlen);
	    }
	}
    }
    return;
}

#endif /* defined(THROUGHPUT) */ 

/*************************************************************************
**
** Routines to checksum a file.
**
** Currently supported algorithms are:  CRC, MD5 and ADLER32.
**
**
*************************************************************************/
static int CheckMethod = 1;

void SetCheckMethod(const char *method)
{
    if ((strcasecmp(method, "md5") == 0)
	|| (strcasecmp(method, "rfc1321") == 0))
	CheckMethod = 0;
    else if ((strcasecmp(method, "crc") == 0)
	     || (strcasecmp(method, "posix") == 0))
	CheckMethod = 1;
    else if ((strcasecmp(method, "adler32") == 0)
	     || (strcasecmp(method, "rfc1950") == 0))
	CheckMethod = 2;
    else {
	reply(500, "Unrecognized checksum method");
	return;
    }
    switch (CheckMethod) {
    default:
	reply(200, "Checksum method is now: MD5 (RFC1321)");
	break;
    case 1:
	reply(200, "Checksum method is now: CRC (POSIX)");
	break;
    case 2:
	reply(200, "Checksum method is now: ADLER32 (RFC1950)");
	break;
    }
}

void ShowCheckMethod(void)
{
    switch (CheckMethod) {
    default:
	reply(200, "Current checksum method: MD5 (RFC1321)");
	break;
    case 1:
	reply(200, "Current checksum method: CRC (POSIX)");
	break;
    case 2:
	reply(200, "Current checksum method: ADLER32 (RFC1950)");
	break;
    }
}

void CheckSum(char *pathname)
{
    char *cmd;
    char buf[MAXPATHLEN];
    FILE *cmdf;
    struct stat st;

    if (stat(pathname, &st) == 0) {
	if ((st.st_mode & S_IFMT) != S_IFREG) {
	    reply(500, "%s: not a plain file.", pathname);
	    return;
	}
    }
    else {
	perror_reply(550, pathname);
	return;
    }

    switch (CheckMethod) {
    default:
	cmd = "/bin/md5sum";
	break;
    case 1:
	cmd = "/bin/cksum";
	break;
    }

    if (strlen(cmd) + 1 + strlen(pathname) + 1 > sizeof(buf)) {
	reply(500, "Pathname too long");
	return;
    }
    snprintf(buf, sizeof(buf), "%s %s", cmd, pathname);

    cmdf = ftpd_popen(buf, "r", 0);
    if (!cmdf) {
	perror_reply(550, cmd);
    }
    else {
	if (fgets(buf, sizeof buf, cmdf)) {
	    char *crptr = strchr(buf, '\n');
	    if (crptr != NULL)
		*crptr = '\0';
	    reply(200, "%s", buf);
	}
	ftpd_pclose(cmdf);
    }
}

void CheckSumLastFile(void)
{
    extern char LastFileTransferred[];

    if (LastFileTransferred[0] == '\0')
	reply(500, "Nothing transferred yet");
    else
	CheckSum(LastFileTransferred);
}

/************************************************************************
**
** Update a running Adler-32 checksum with the bytes buf[0..len-1]
** and return the updated checksum. The Adler-32 checksum should be
** initialized to 1.
**
** Usage example:
**
**    unsigned long adler = 1L;
**
**    while (read_buffer(buffer, length) != EOF) {
**        adler = update_adler32(adler, buffer, length);
**    }
**
**   if (adler != original_adler) error();
*************************************************************************/
#define BASE 65521 /* largest prime smaller than 65536 */

unsigned long update_adler32(unsigned long adler, unsigned char *buf, int len)
{
    unsigned long s1 = adler & 0xffff;
    unsigned long s2 = (adler >> 16) & 0xffff;
    int n;

    for (n = 0; n < len; n++) {
        s1 = (s1 + buf[n]) % BASE;
        s2 = (s2 + s1)     % BASE;
    }
    return (s2 << 16) + s1;
}

/* Return the adler32 of the bytes buf[0..len-1] */

unsigned long adler32(unsigned char *buf, int len)
{
    return update_adler32(1L, buf, len);
}

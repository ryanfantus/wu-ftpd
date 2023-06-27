/*************************************************************
 * Problem: between login and logout happens the chroot,
 * so utmp must be kept open!
 *************************************************************/

/************************************************************* 
 * header 
 *************************************************************/

#include "config.h"
 
#include <sys/types.h>
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
#include <sys/stat.h>
#if defined(HAVE_FCNTL_H)
#  include <fcntl.h>
#endif /* defined(HAVE_FCNTL_H) */ 
#include <utmp.h>
#if defined(SVR4)
#  if !defined(NO_UTMPX)
#    include <utmpx.h>
#    if !defined(_SCO_DS)
#      include <sac.h>
#    endif /* !defined(_SCO_DS) */ 
#  endif /* !defined(NO_UTMPX) */ 
#endif /* defined(SVR4) */ 
#if defined(BSD)
#  include <strings.h>
#else /* !(defined(BSD)) */ 
#  include <string.h>
#endif /* !(defined(BSD)) */ 
#if defined(HAVE_SYS_SYSLOG_H)
#  include <sys/syslog.h>
#endif /* defined(HAVE_SYS_SYSLOG_H) */ 
#if defined(HAVE_SYSLOG_H) || (!defined(AUTOCONF) && !defined(HAVE_SYS_SYSLOG_H))
#  include <syslog.h>
#endif /* defined(HAVE_SYSLOG_H) || (!defined(AUTOCONF) && !defined(HAVE_SYS_SYSLOG_H)) */ 
#if defined(__FreeBSD__)
#  include <netinet/in.h>
#  include <arpa/inet.h>
#  include <netdb.h>
#endif /* defined(__FreeBSD__) */ 

#include <signal.h>
 
#include "pathnames.h"
#include "proto.h"

/************************************************************* 
 * variables
 *************************************************************/

/* Descriptor for the file and position.  */
static int   file_fd = -1;
static off_t file_offset;

/* Locking timeout.  */
#if !defined(TIMEOUT)
#  define TIMEOUT 1
#endif /* !defined(TIMEOUT) */ 

/* Do-nothing handler for locking timeout.  */
static void timeout_handler (int signum) {}

/************************************************************* 
 * UTMP put one entry
 *************************************************************/

static int getut (const struct utmp *id, struct utmp *buf)
{
  while (1)
  {
    /* Read the next entry.  */
    if (read (file_fd, buf, sizeof (struct utmp)) != sizeof (struct utmp))
    {
      file_offset = -1l;
      return -1;
    }

    file_offset += sizeof (struct utmp);

    if (
#if _HAVE_UT_TYPE - 0
        (id->ut_type  == USER_PROCESS || id->ut_type  == DEAD_PROCESS) &&
        (buf->ut_type == USER_PROCESS || buf->ut_type == DEAD_PROCESS) &&
#endif /* _HAVE_UT_TYPE - 0 */ 
        (strncmp(id->ut_line, buf->ut_line, sizeof buf->ut_line)==0)      )
      break;
  }
  return 0;
}

static struct utmp * utmpentry (const struct utmp *data)
{
  struct utmp buf;
  struct utmp *pbuf;
  int found;

  struct flock fl;
  struct sigaction action, old_action;
  unsigned int old_timeout;

  if (file_fd < 0)
  {
    file_fd = open (_PATH_UTMP, O_RDWR);
    if (file_fd == -1)
    {
      syslog(LOG_ERR, "utmp %s %m", _PATH_UTMP);
      return NULL;
    }
  }

  lseek (file_fd, 0, SEEK_SET);
  file_offset = 0;

  old_timeout = alarm (0);
  action.sa_handler = timeout_handler;
  sigemptyset (&action.sa_mask);
  action.sa_flags = 0;
  sigaction (SIGALRM, &action, &old_action);
  alarm (TIMEOUT);

  memset (&fl, '\0', sizeof (struct flock));
  fl.l_type = F_WRLCK;
  fl.l_whence = SEEK_SET;
  fcntl ((file_fd), F_SETLKW, &fl);

  /* Find the correct place to insert the data.  */
  found = getut (data, &buf);

  if (found < 0)
  {
    /* We append the next entry.  */
    file_offset = lseek (file_fd, 0, SEEK_END);
    if (file_offset % sizeof (struct utmp) != 0)
    {
      file_offset -= file_offset % sizeof (struct utmp);
      ftruncate (file_fd, file_offset);

      if (lseek (file_fd, 0, SEEK_END) < 0)
      {
        pbuf = NULL;
        goto unlock_return;
      }
    }
  }
  else
  {
    /* We replace the just read entry.  */
    file_offset -= sizeof (struct utmp);
    lseek (file_fd, file_offset, SEEK_SET);
  }

  if (write (file_fd, data, sizeof (struct utmp)) != sizeof (struct utmp))
  {
    /* If we appended a new record and this is only partially written then
       remove it.  */
    if (found < 0)
      (void) ftruncate (file_fd, file_offset);
    pbuf = NULL;
  }
  else
  {
    file_offset += sizeof (struct utmp);
    pbuf = (struct utmp *) data;
  }

  unlock_return:
  fl.l_type = F_UNLCK;
  fcntl ((file_fd), F_SETLKW, &fl);
  sigaction (SIGALRM, &old_action, NULL);
  alarm (old_timeout);
  return pbuf;
}

/************************************************************* 
 * UTMP  put one login or logout entry
 *************************************************************/

void wu_logutmp (const char *line, const char *name, const char *host, const int login)
{
  struct utmp ut;

  memset (&ut, 0, sizeof (ut));

#if _HAVE_UT_PID - 0
  ut.ut_pid = getpid ();
#endif /* _HAVE_UT_PID - 0 */ 

  strncpy (ut.ut_line, line, sizeof ut.ut_line);

#if _HAVE_UT_TV - 0
  gettimeofday (&ut.ut_tv, NULL);
#else /* !(_HAVE_UT_TV - 0) */ 
  time (&ut.ut_time);
#endif /* !(_HAVE_UT_TV - 0) */ 

if (login)
{
/******** 
 * login 
 ********/

#if _HAVE_UT_TYPE - 0
    ut.ut_type = USER_PROCESS;
#endif /* _HAVE_UT_TYPE - 0 */ 

    strncpy (ut.ut_name, name, sizeof ut.ut_name);

#if _HAVE_UT_HOST - 0
    strncpy (ut.ut_host, host, sizeof ut.ut_host);
#endif /* _HAVE_UT_HOST - 0 */ 

    /* Write the entry.  */
    utmpentry (&ut);
  }
  else
  {
/********* 
 * logout
 *********/
#if _HAVE_UT_TYPE - 0
    ut.ut_type = DEAD_PROCESS;
#endif /* _HAVE_UT_TYPE - 0 */ 

    strncpy (ut.ut_name, "", sizeof ut.ut_name);

#if _HAVE_UT_HOST - 0
    strncpy (ut.ut_host, "", sizeof ut.ut_host);
#endif /* _HAVE_UT_HOST - 0 */ 
#if defined(HAVE_UT_UT_EXIT_E_TERMINATION) || (!defined(AUTOCONF) && !defined(LINUX))
    ut.ut_exit.e_termination = 0;
    ut.ut_exit.e_exit = 0;
#endif /* defined(HAVE_UT_UT_EXIT_E_TERMINATION) || (!defined(AUTOCONF) && !defined(LINUX)) */ 

    /* Write the entry.  */
    utmpentry (&ut);
  }
}

/************************************************************* 
 * thats it !!!
 *************************************************************/

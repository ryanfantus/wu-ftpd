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
   
  $Id: loadavg.h,v 1.9 2011/10/20 22:58:10 wmaton Exp $  
   
****************************************************************************/
#include <unistd.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <setjmp.h>
#include <string.h>
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
#include <errno.h>
#include <sysexits.h>

#include <sys/param.h>
#include <sys/types.h>
#include <sys/stat.h>
#if !defined(__QNX__)
/* in QNX this grabs bogus LOCK_* manifests */
#  include <sys/file.h>
#endif /* !defined(__QNX__) */ 
#include <sys/wait.h>
#include <limits.h>
#include <fcntl.h>
#include <signal.h>
#include <netdb.h>
#include <pwd.h>

/**********************************************************************
**  Operating system configuration.
**
**      Unless you are porting to a new OS, you shouldn't have to
**      change these.
**********************************************************************/

/*
   **  HP-UX -- tested for 8.07, 9.00, and 9.01.
   **
   **      If V4FS is defined, compile for HP-UX 10.0.
   **      11.x support from Richard Allen <ra@hp.is>.
 */

#if defined(__hpux)
#  define SYSTEM5        1	/* include all the System V defines */
#  define LA_TYPE        LA_HPUX
#  if defined(V4FS)
		/* HP-UX 10.x */
#    define _PATH_UNIX            "/stand/vmunix"
#  else /* !(defined(V4FS)) */ 
		/* HP-UX 9.x */
#    define _PATH_UNIX            "/hp-ux"
#  endif /* !(defined(V4FS)) */ 
#endif /* defined(__hpux) */ 

/*
   **  IBM AIX 4.x
 */

#if defined(_AIX4)
#  define _AIX3          1	/* pull in AIX3 stuff */
#endif /* defined(_AIX4) */ 

/*
   **  IBM AIX 3.x -- actually tested for 3.2.3
 */

#if defined(_AIX3)
#  include <paths.h>
#  include <sys/machine.h>	/* to get byte order */
#  include <sys/select.h>
#  define LA_TYPE        LA_INT
#  define FSHIFT         16
#  define LA_AVENRUN     "avenrun"
#endif /* defined(_AIX3) */ 

/*
   **  IBM AIX 2.2.1 -- actually tested for osupdate level 2706+1773
   **
   **      From Mark Whetzel <markw@wg.waii.com>.
 */

#if defined(AIX)
#  include <paths.h>
#  define LA_TYPE        LA_SUBR	/* use our ported loadavgd daemon */
#endif /* defined(AIX) */ 

/*
   **  Silicon Graphics IRIX
   **
   **      Compiles on 4.0.1.
   **
   **      Use IRIX64 instead of IRIX for 64-bit IRIX (6.0).
   **      Use IRIX5 instead of IRIX for IRIX 5.x.
   **
   **      This version tries to be adaptive using _MIPS_SIM:
   **              _MIPS_SIM == _ABIO32 (= 1)    Abi: -32  on IRIX 6.2
   **              _MIPS_SIM == _ABIN32 (= 2)    Abi: -n32 on IRIX 6.2
   **              _MIPS_SIM == _ABI64  (= 3)    Abi: -64 on IRIX 6.2
   **
   **              _MIPS_SIM is 1 also on IRIX 5.3
   **
   **      IRIX64 changes from Mark R. Levinson <ml@cvdev.rochester.edu>.
   **      IRIX5 changes from Kari E. Hurtta <Kari.Hurtta@fmi.fi>.
   **      Adaptive changes from Kari E. Hurtta <Kari.Hurtta@fmi.fi>.
 */

#if defined(__sgi)
#  if !defined(IRIX)
#    define IRIX
#  endif /* !defined(IRIX) */ 
#  if _MIPS_SIM > 0 && !defined(IRIX5)
#    define IRIX5			/* IRIX5 or IRIX6 */
#  endif /* _MIPS_SIM > 0 && !defined(IRIX5) */ 
#  if _MIPS_SIM > 1 && !defined(IRIX6) && !defined(IRIX64)
#    define IRIX6			/* IRIX6 */
#  endif /* _MIPS_SIM > 1 && !defined(IRIX6) && !defined(IRIX64) */ 
#endif /* defined(__sgi) */ 

#if defined(IRIX)
#  define SYSTEM5        1	/* this is a System-V derived system */
#  if defined(IRIX6)
#    define LA_TYPE       LA_IRIX6	/* figure out at run time */
#  else /* !(defined(IRIX6)) */ 
#    define LA_TYPE       LA_INT
#  endif /* !(defined(IRIX6)) */ 
#  if defined(IRIX64) || defined(IRIX5) || defined(IRIX6)
#    include <sys/cdefs.h>
#    include <paths.h>
#  endif /* defined(IRIX64) || defined(IRIX5) || defined(IRIX6) */ 
#endif /* defined(IRIX) */ 

/*
   **  SunOS and Solaris
   **
   **      Tested on SunOS 4.1.x (a.k.a. Solaris 1.1.x) and
   **      Solaris 2.4 (a.k.a. SunOS 5.4).
 */

#if defined(sun) && !defined(BSD)

#  if defined(SOLARIS_2_3)
#    define SOLARIS       20300	/* for back compat only -- use -DSOLARIS=20300 */
#  endif /* defined(SOLARIS_2_3) */ 
#  if !defined(SOLARIS) && defined(sun) && (defined(__svr4__) || defined(__SVR4))
#    define SOLARIS       1		/* unknown Solaris version */
#  endif /* !defined(SOLARIS) && defined(sun) && (defined(__svr4__) || defined(__SVR4)) */ 
#  if defined(SOLARIS)
			/* Solaris 2.x (a.k.a. SunOS 5.x) */
#    if !defined(__svr4__)
#      define __svr4__		/* use all System V Releae 4 defines below */
#    endif /* !defined(__svr4__) */ 
#    if !defined(_PATH_UNIX)
#      define _PATH_UNIX           "/dev/ksyms"
#    endif /* !defined(_PATH_UNIX) */ 
#    if SOLARIS >= 20500 || (SOLARIS < 10000 && SOLARIS >= 205)
#      if SOLARIS < 207 || (SOLARIS > 10000 && SOLARIS < 20700)
#        if !defined(LA_TYPE)
#          define LA_TYPE    LA_KSTAT	/* use kstat(3k) -- may work in < 2.5 */
#        endif /* !defined(LA_TYPE) */ 
#      endif /* SOLARIS < 207 || (SOLARIS > 10000 && SOLARIS < 20700) */ 
#    endif /* SOLARIS >= 20500 || (SOLARIS < 10000 && SOLARIS >= 205) */ 
#    if SOLARIS >= 20700 || (SOLARIS < 10000 && SOLARIS >= 207)
#      if !defined(LA_TYPE)
#        define LA_TYPE     LA_SUBR	/* getloadavg(3c) appears in 2.7 */
#      endif /* !defined(LA_TYPE) */ 
#    endif /* SOLARIS >= 20700 || (SOLARIS < 10000 && SOLARIS >= 207) */ 
#  else /* !(defined(SOLARIS)) */ 
			/* SunOS 4.0.3 or 4.1.x */
#    include <memory.h>
#    include <vfork.h>
#    if defined(SUNOS403)
			/* special tweaking for SunOS 4.0.3 */
#      include <malloc.h>
#      define BSD4_3       1		/* 4.3 BSD-based */
#    endif /* defined(SUNOS403) */ 
#  endif /* !(defined(SOLARIS)) */ 
#  if !defined(LA_TYPE)
#    define LA_TYPE       LA_INT
#  endif /* !defined(LA_TYPE) */ 
#endif /* defined(sun) && !defined(BSD) */ 

/*
   **  DG/UX
   **
   **      Tested on 5.4.2 and 5.4.3.  Use DGUX_5_4_2 to get the
   **      older support.
   **      5.4.3 changes from Mark T. Robinson <mtr@ornl.gov>.
 */

#if defined(DGUX_5_4_2)
#  define DGUX           1
#endif /* defined(DGUX_5_4_2) */ 

#if defined(DGUX)
#  define SYSTEM5        1
#  define LA_TYPE        LA_DGUX

/* these include files must be included early on DG/UX */
#  include <netinet/in.h>
#  include <arpa/inet.h>

/* compiler doesn't understand const? */
#  define const

#endif /* defined(DGUX) */ 

/*
   **  Digital Ultrix 4.2A or 4.3
   **
   **      Apparently, fcntl locking is broken on 4.2A, in that locks are
   **      not dropped when the process exits.  This causes major problems,
   **      so flock is the only alternative.
 */

#if defined(ultrix)
#  if defined(vax)
#    define LA_TYPE       LA_FLOAT
#  else /* !(defined(vax)) */ 
#    define LA_TYPE       LA_INT
#    define LA_AVENRUN    "avenrun"
#  endif /* !(defined(vax)) */ 
#endif /* defined(ultrix) */ 

/*
   **  OSF/1 for KSR.
   **
   **      Contributed by Todd C. Miller <Todd.Miller@cs.colorado.edu>
 */

#if defined(__ksr__)
#  define __osf__        1	/* get OSF/1 defines below */
#endif /* defined(__ksr__) */ 

/*
   **  OSF/1 for Intel Paragon.
   **
   **      Contributed by Jeff A. Earickson <jeff@ssd.intel.com>
   **      of Intel Scalable Systems Divison.
 */

#if defined(__PARAGON__)
#  define __osf__        1	/* get OSF/1 defines below */
#endif /* defined(__PARAGON__) */ 

/*
   **  OSF/1 (tested on Alpha) -- now known as Digital UNIX.
   **
   **      Tested for 3.2 and 4.0.
 */

#if defined(__osf__)
#  define LA_TYPE        LA_ALPHAOSF
#endif /* defined(__osf__) */ 

/*
   **  NeXTstep
 */

#if defined(NeXT)
#  if !defined(LA_TYPE)
#    define LA_TYPE       LA_MACH
#  endif /* !defined(LA_TYPE) */ 
#endif /* defined(NeXT) */ 

/*
   **  4.4 BSD
   **
   **      See also BSD defines.
 */

#if defined(BSD4_4) && !defined(__bsdi__) && !defined(__GNU__)
#  include <paths.h>
#  include <sys/cdefs.h>
#  if !defined(LA_TYPE)
#    define LA_TYPE       LA_SUBR
#  endif /* !defined(LA_TYPE) */ 
#endif /* defined(BSD4_4) && !defined(__bsdi__) && !defined(__GNU__) */ 

/*
   **  BSD/OS (was BSD/386) (all versions)
   **      From Tony Sanders, BSDI
 */

#if defined(__bsdi__)
#  include <paths.h>
#  include <sys/cdefs.h>
#  if !defined(LA_TYPE)
#    define LA_TYPE       LA_SUBR
#  endif /* !defined(LA_TYPE) */ 
#endif /* defined(__bsdi__) */ 

/*
   **  QNX 4.2x
   **      Contributed by Glen McCready <glen@qnx.com>.
   **
   **      Should work with all versions of QNX.
 */

#if defined(__QNX__)
#  include <unix.h>
#  include <sys/select.h>
#  define LA_TYPE        LA_ZERO
#endif /* defined(__QNX__) */ 

/*
   **  FreeBSD / NetBSD / OpenBSD (all architectures, all versions)
   **
   **  4.3BSD clone, closer to 4.4BSD      for FreeBSD 1.x and NetBSD 0.9x
   **  4.4BSD-Lite based                   for FreeBSD 2.x and NetBSD 1.x
   **
   **      See also BSD defines.
 */

#if defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD__)
#  include <paths.h>
#  include <sys/cdefs.h>
#  if !defined(LA_TYPE)
#    define LA_TYPE       LA_SUBR
#  endif /* !defined(LA_TYPE) */ 
#  if defined(__FreeBSD__)
#    if __FreeBSD__ == 2
#      include <osreldate.h>		/* and this works */
#      if __FreeBSD_version >= 199512	/* 2.2-current right now */
#        include <libutil.h>
#      endif /* __FreeBSD_version >= 199512	/* 2.2-current right now */ */ 
#    endif /* __FreeBSD__ == 2 */ 
#  endif /* defined(__FreeBSD__) */ 
#endif /* defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD__) */ 

/*
   **  Mach386
   **
   **      For mt Xinu's Mach386 system.
 */

#if defined(MACH) && defined(i386) && !defined(__GNU__)
#  define MACH386        1
#  if !defined(LA_TYPE)
#    define LA_TYPE       LA_FLOAT
#  endif /* !defined(LA_TYPE) */ 
#endif /* defined(MACH) && defined(i386) && !defined(__GNU__) */ 

/*
   **  GNU OS (hurd)
   **      Largely BSD & posix compatible.
   **      Port contributed by Miles Bader <miles@gnu.ai.mit.edu>.
 */

#if defined(__GNU_HURD__)
#  define LA_TYPE        LA_MACH
#endif /* defined(__GNU_HURD__) */ 

/*
   **  4.3 BSD -- this is for very old systems
   **
   **      Should work for mt Xinu MORE/BSD and Mips UMIPS-BSD 2.1.
   **
   **      You'll also have to install a new resolver library.
   **      I don't guarantee that support for this environment is complete.
 */

#if defined(oldBSD43) || defined(MORE_BSD) || defined(umipsbsd)
#  if !defined(LA_TYPE)
#    define LA_TYPE       LA_FLOAT
#  endif /* !defined(LA_TYPE) */ 
#endif /* defined(oldBSD43) || defined(MORE_BSD) || defined(umipsbsd) */ 

/*
   **  SCO Unix
   **
   **      This includes three parts:
   **
   **      The first is for SCO OpenServer 5.
   **      (Contributed by Keith Reynolds <keithr@sco.COM>).
   **
   **              SCO OpenServer 5 has a compiler version number macro,
   **              which we can use to figure out what version we're on.
   **              This may have to change in future releases.
   **
   **      The second is for SCO UNIX 3.2v4.2/Open Desktop 3.0.
   **      (Contributed by Philippe Brand <phb@colombo.telesys-innov.fr>).
   **
   **      The third is for SCO UNIX 3.2v4.0/Open Desktop 2.0 and earlier.
 */

/* SCO OpenServer 5 */
#if _SCO_DS >= 1
#  include <paths.h>
#  if !defined(LA_TYPE)
#    define LA_TYPE       LA_DEVSHORT
#  endif /* !defined(LA_TYPE) */ 
#  define _PATH_AVENRUN  "/dev/table/avenrun"
#  if !defined(_SCO_unix_4_2)
#    define _SCO_unix_4_2
#  endif /* !defined(_SCO_unix_4_2) */ 
#endif /* _SCO_DS >= 1 */ 

/* SCO UNIX 3.2v4.2/Open Desktop 3.0 */
#if defined(_SCO_unix_4_2)
#  define _SCO_unix_
#endif /* defined(_SCO_unix_4_2) */ 

/* SCO UNIX 3.2v4.0 Open Desktop 2.0 and earlier */
#if defined(_SCO_unix_)
#  include <sys/stream.h>		/* needed for IP_SRCROUTE */
#  define SYSTEM5        1	/* include all the System V defines */
#  define _PATH_UNIX             "/unix"
#  if !defined(_SCO_DS)
#    define LA_TYPE       LA_SHORT
#  endif /* !defined(_SCO_DS) */ 
#endif /* defined(_SCO_unix_) */ 

/*
   **  ISC (SunSoft) Unix.
   **
   **      Contributed by J.J. Bailey <jjb@jagware.bcc.com>
 */

#if defined(ISC_UNIX)
#  include <net/errno.h>
#  include <sys/stream.h>		/* needed for IP_SRCROUTE */
#  include <sys/bsdtypes.h>
#  define SYSTEM5        1	/* include all the System V defines */
#  define LA_TYPE        LA_SHORT
#  define _PATH_UNIX             "/unix"
#endif /* defined(ISC_UNIX) */ 

/*
   **  Altos System V (5.3.1)
   **      Contributed by Tim Rice <tim@trr.metro.net>.
 */

#if defined(ALTOS_SYSTEM_V)
#  include <sys/stream.h>
#  include <limits.h>
#  define SYSTEM5        1	/* include all the System V defines */
#  define LA_TYPE        LA_SHORT
#endif /* defined(ALTOS_SYSTEM_V) */ 

/*
   **  ConvexOS 11.0 and later
   **
   **      "Todd C. Miller" <millert@mroe.cs.colorado.edu> claims this
   **      works on 9.1 as well.
   **
   **  ConvexOS 11.5 and later, should work on 11.0 as defined.
   **  For pre-ConvexOOS 11.0, define NEEDGETOPT, undef IDENTPROTO
   **
   **      Eric Schnoebelen (eric@cirr.com) For CONVEX Computer Corp.
   **              (now the CONVEX Technologies Center of Hewlett Packard)
 */

#if defined(_CONVEX_SOURCE)
#  define LA_TYPE        LA_FLOAT
#endif /* defined(_CONVEX_SOURCE) */ 

/*
   **  RISC/os 4.52
   **
   **      Gives a ton of warning messages, but otherwise compiles.
 */

#if defined(RISCOS)
#  define LA_TYPE        LA_INT
#  define LA_AVENRUN     "avenrun"
#  define _PATH_UNIX     "/unix"
#endif /* defined(RISCOS) */ 

/*
   **  Linux 0.99pl10 and above...
   **
   **  Thanks to, in reverse order of contact:
   **
   **      John Kennedy <warlock@csuchico.edu>
   **      Andrew Pam <avatar@aus.xanadu.com>
   **      Florian La Roche <rzsfl@rz.uni-sb.de>
   **      Karl London <karl@borg.demon.co.uk>
   **
   **  Last compiled against:      [06/10/96 @ 09:21:40 PM (Monday)]
   **      sendmail 8.8-a4         named bind-4.9.4-T4B    db-1.85
   **      gcc 2.7.2               libc-5.3.12             linux 2.0.0
   **
   **  NOTE: Override HASFLOCK as you will but, as of 1.99.6, mixed-style
   **      file locking is no longer allowed.  In particular, make sure
   **      your DBM library and sendmail are both using either flock(2)
   **      *or* fcntl(2) file locking, but not both.
 */

#if defined(__linux__)
#  define BSD            1	/* include BSD defines */
#  if !defined(LA_TYPE)
#    define LA_TYPE       LA_PROCSTR
#  endif /* !defined(LA_TYPE) */ 
#  include <sys/sysmacros.h>
#endif /* defined(__linux__) */ 

/*
   **  DELL SVR4 Issue 2.2, and others
   **      From Kimmo Suominen <kim@grendel.lut.fi>
   **
   **      It's on #ifdef DELL_SVR4 because Solaris also gets __svr4__
   **      defined, and the definitions conflict.
   **
   **      Peter Wemm <peter@perth.DIALix.oz.au> claims that the setreuid
   **      trick works on DELL 2.2 (SVR4.0/386 version 4.0) and ESIX 4.0.3A
   **      (SVR4.0/386 version 3.0).
 */

#if defined(DELL_SVR4)
				/* no changes necessary */
				/* see general __svr4__ defines below */
#endif /* defined(DELL_SVR4) */ 

/*
   **  Apple A/UX 3.0
 */

#if defined(_AUX_SOURCE)
#  include <sys/sysmacros.h>
#  define BSD			/* has BSD routines */
#  if !defined(LA_TYPE)
#    define LA_TYPE       LA_INT
#    define FSHIFT        16
#  endif /* !defined(LA_TYPE) */ 
#  define LA_AVENRUN     "avenrun"
#  if !defined(_PATH_UNIX)
#    define _PATH_UNIX            "/unix"	/* should be in <paths.h> */
#  endif /* !defined(_PATH_UNIX) */ 
#endif /* defined(_AUX_SOURCE) */ 

/*
   **  Encore UMAX V
   **
   **      Not extensively tested.
 */

#if defined(UMAXV)
#endif /* defined(UMAXV) */ 

/*
   **  Stardent Titan 3000 running TitanOS 4.2.
   **
   **      Must be compiled in "cc -43" mode.
   **
   **      From Kate Hedstrom <kate@ahab.rutgers.edu>.
   **
   **      Note the tweaking below after the BSD defines are set.
 */

#if defined(titan)
#endif /* defined(titan) */ 

/*
   **  Sequent DYNIX 3.2.0
   **
   **      From Jim Davis <jdavis@cs.arizona.edu>.
 */

#if defined(sequent)
#  define BSD            1
#  define LA_TYPE        LA_FLOAT
#  if !defined(_PATH_UNIX)
#    define _PATH_UNIX            "/dynix"
#  endif /* !defined(_PATH_UNIX) */ 
#endif /* defined(sequent) */ 

/*
   **  Sequent DYNIX/ptx v2.0 (and higher)
   **
   **      For DYNIX/ptx v1.x, undefine HASSETREUID.
   **
   **      From Tim Wright <timw@sequent.com>.
   **      Update from Jack Woolley <jwoolley@sctcorp.com>, 26 Dec 1995,
   **              for DYNIX/ptx 4.0.2.
 */

#if defined(_SEQUENT_)
#  include <sys/stream.h>
#  define SYSTEM5        1	/* include all the System V defines */
#  define LA_TYPE        LA_INT
#endif /* defined(_SEQUENT_) */ 

/*
   **  Cray Unicos
   **
   **      Ported by David L. Kensiski, Sterling Sofware <kensiski@nas.nasa.gov>
 */

#if defined(UNICOS)
#  define SYSTEM5        1	/* include all the System V defines */
#  define LA_TYPE        LA_ZERO
#endif /* defined(UNICOS) */ 

/*
   **  Apollo DomainOS
   **
   **  From Todd Martin <tmartint@tus.ssi1.com> & Don Lewis <gdonl@gv.ssi1.com>
   **
   **  15 Jan 1994; updated 2 Aug 1995
   **
 */

#if defined(apollo)
#  define LA_TYPE        LA_SUBR	/* use getloadavg.c */
#endif /* defined(apollo) */ 

/*
   **  UnixWare 2.x
 */

#if defined(UNIXWARE2)
#  define UNIXWARE       1
#endif /* defined(UNIXWARE2) */ 

/*
   **  UnixWare 1.1.2.
   **
   **      Updated by Petr Lampa <lampa@fee.vutbr.cz>.
   **      From Evan Champion <evanc@spatial.synapse.org>.
 */

#if defined(UNIXWARE)
#  include <sys/mkdev.h>
#  define SYSTEM5                1
#  define LA_TYPE                LA_ZERO
#  define _PATH_UNIX             "/unix"
#endif /* defined(UNIXWARE) */ 

/*
   **  Intergraph CLIX 3.1
   **
   **      From Paul Southworth <pauls@locust.cic.net>
 */

#if defined(CLIX)
#  define SYSTEM5        1	/* looks like System V */
#endif /* defined(CLIX) */ 

/*
   **  NCR MP-RAS 2.x (SysVr4) with Wollongong TCP/IP
   **
   **      From Kevin Darcy <kevin@tech.mis.cfc.com>.
 */

#if defined(NCR_MP_RAS2)
#  include <sys/sockio.h>
#  define __svr4__
#endif /* defined(NCR_MP_RAS2) */ 

/*
   **  NCR MP-RAS 3.x (SysVr4) with STREAMware TCP/IP
   **
   **      From Tom Moore <Tom.Moore@DaytonOH.NCR.COM>
 */

#if defined(NCR_MP_RAS3)
#  define __svr4__
#endif /* defined(NCR_MP_RAS3) */ 

/*
   **  Tandem NonStop-UX SVR4
   **
   **      From Rick McCarty <mccarty@mpd.tandem.com>.
 */

#if defined(NonStop_UX_BXX)
#  define __svr4__
#endif /* defined(NonStop_UX_BXX) */ 

/*
   **  Hitachi 3050R & 3050RX Workstations running HI-UX/WE2.
   **
   **      Tested for 1.04 and 1.03
   **      From Akihiro Hashimoto ("Hash") <hash@dominic.ipc.chiba-u.ac.jp>.
 */

#if defined(__H3050R)
#  define SYSTEM5        1	/* include all the System V defines */
#  define LA_TYPE        LA_FLOAT
#  if !defined(_PATH_UNIX)
#    define _PATH_UNIX            "/HI-UX"
#  endif /* !defined(_PATH_UNIX) */ 
#endif /* defined(__H3050R) */ 

/*
   **  Amdahl UTS System V 2.1.5 (SVr3-based)
   **
   **    From: Janet Jackson <janet@dialix.oz.au>.
 */

#if defined(_UTS)
#  include <sys/sysmacros.h>
#  define LA_TYPE        LA_ZERO	/* doesn't have load average */
#  define _PATH_UNIX             "/unix"
#endif /* defined(_UTS) */ 

/*
   **  Cray Computer Corporation's CSOS
   **
   **      From Scott Bolte <scott@craycos.com>.
 */

#if defined(_CRAYCOM)
#  define SYSTEM5        1	/* include all the System V defines */
#  define LA_TYPE        LA_ZERO
#endif /* defined(_CRAYCOM) */ 

/*
   **  Sony NEWS-OS 4.2.1R and 6.0.3
   **
   **      From Motonori NAKAMURA <motonori@cs.ritsumei.ac.jp>.
 */

#if defined(sony_news)
#  if !defined(__svr4)
#    if !defined(BSD)
#      define BSD			/* has BSD routines */
#    endif /* !defined(BSD) */ 
#    define LA_TYPE       LA_INT
#  else /* !(!defined(__svr4)) */ 
#    if !defined(__svr4__)
#      define __svr4__		/* use all System V Releae 4 defines below */
#    endif /* !defined(__svr4__) */ 
#    define LA_TYPE       LA_READKSYM	/* use MIOC_READKSYM ioctl */
#    define _PATH_UNIX            "/stand/unix"
#  endif /* !(!defined(__svr4)) */ 
#endif /* defined(sony_news) */ 

/*
   **  Omron LUNA/UNIOS-B 3.0, LUNA2/Mach and LUNA88K Mach
   **
   **      From Motonori NAKAMURA <motonori@cs.ritsumei.ac.jp>.
 */

#if defined(luna)
#  if defined(uniosb)
#    define LA_TYPE       LA_INT
#  endif /* defined(uniosb) */ 
#  if defined(luna2)
#    define LA_TYPE       LA_SUBR
#  endif /* defined(luna2) */ 
#  if defined(luna88k)
#    define LA_TYPE       LA_INT
#  endif /* defined(luna88k) */ 
#endif /* defined(luna) */ 

/*
   **  NEC EWS-UX/V 4.2 (with /usr/ucb/cc)
   **
   **      From Motonori NAKAMURA <motonori@cs.ritsumei.ac.jp>.
 */

#if defined(nec_ews_svr4) || defined(_nec_ews_svr4)
#  if !defined(__svr4__)
#    define __svr4__		/* use all System V Releae 4 defines below */
#  endif /* !defined(__svr4__) */ 
#  define LA_TYPE        LA_READKSYM	/* use MIOC_READSYM ioctl */
#endif /* defined(nec_ews_svr4) || defined(_nec_ews_svr4) */ 

/*
   **  Fujitsu/ICL UXP/DS (For the DS/90 Series)
   **
   **      From Diego R. Lopez <drlopez@cica.es>.
   **      Additional changes from Fumio Moriya and Toshiaki Nomura of the
   **              Fujitsu Fresoftware gruop <dsfrsoft@oai6.yk.fujitsu.co.jp>.
 */

#if defined(__uxp__)
#  include <arpa/nameser.h>
#  include <sys/sysmacros.h>
#  include <sys/mkdev.h>
#  define __svr4__
#  define _PATH_UNIX             "/stand/unix"
#endif /* defined(__uxp__) */ 

/*
   **  Pyramid DC/OSx
   **
   **      From Earle Ake <akee@wpdiss1.wpafb.af.mil>.
 */

#if defined(DCOSx)
#endif /* defined(DCOSx) */ 

/*
   **  Concurrent Computer Corporation Maxion
   **
   **      From Donald R. Laster Jr. <laster@access.digex.net>.
 */

#if defined(__MAXION__)
#  include <sys/stream.h>
#  define __svr4__               1	/* SVR4.2MP */
#endif /* defined(__MAXION__) */ 

/*
   **  Harris Nighthawk PowerUX (nh6000 box)
   **
   **  Contributed by Bob Miorelli, Pratt & Whitney <miorelli@pweh.com>
 */

#if defined(_PowerUX)
#  if !defined(__svr4__)
#    define __svr4__
#  endif /* !defined(__svr4__) */ 
#  define LA_TYPE                LA_ZERO
#endif /* defined(_PowerUX) */ 

/*
   **  Siemens Nixdorf Informationssysteme AG SINIX
   **
   **      Contributed by Gerald Rinske <Gerald.Rinske@mch.sni.de>
   **      of Siemens Business Services VAS.
 */

#if defined(sinix)
#endif /* defined(sinix) */ 

/*
   **  CRAY T3E
   **
   **      Contributed by Manu Mahonen <mailadm@csc.fi>
   **      of Center for Scientific Computing.
 */
#if defined(_CRAY)
#endif /* defined(_CRAY) */ 

/**********************************************************************
**  End of Per-Operating System defines
**********************************************************************/

/**********************************************************************
**  More general defines
**********************************************************************/

#if defined(BSD)
#endif /* defined(BSD) */ 

#if defined(__svr4__)
#  define SYSTEM5        1
#  if !defined(_PATH_UNIX)
#    define _PATH_UNIX            "/unix"
#  endif /* !defined(_PATH_UNIX) */ 
#endif /* defined(__svr4__) */ 

#if defined(SYSTEM5)
#  include <sys/sysmacros.h>
#  if !defined(LA_TYPE)
#    if defined(MIOC_READKSYM)
#      define LA_TYPE      LA_READKSYM	/* use MIOC_READKSYM ioctl */
#    else /* !(defined(MIOC_READKSYM)) */ 
#      define LA_TYPE      LA_INT	/* assume integer load average */
#    endif /* !(defined(MIOC_READKSYM)) */ 
#  endif /* !defined(LA_TYPE) */ 
#endif /* defined(SYSTEM5) */ 


/* general POSIX defines */
#if defined(_POSIX_VERSION)
#endif /* defined(_POSIX_VERSION) */ 

/*
   **  Tweaking for systems that (for example) claim to be BSD or POSIX
   **  but don't have all the standard BSD or POSIX routines (boo hiss).
 */

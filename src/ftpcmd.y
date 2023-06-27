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
   
  $Id: ftpcmd.y,v 1.25 2016/03/12 12:56:38 wmaton Exp $  
   
****************************************************************************/ 
/*
 * Grammar for FTP commands.
 * See RFC 959.
 */

%{

#include "config.h"
#include <sys/param.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "ftp.h"
#include <stdio.h>
#include <signal.h>
#include <errno.h>
#include <ctype.h>
#include <pwd.h>
#include <setjmp.h>
#if defined(HAVE_SYS_SYSLOG_H)
#  include <sys/syslog.h>
#endif /* defined(HAVE_SYS_SYSLOG_H) */ 
#if defined(HAVE_SYSLOG_H) || (!defined(AUTOCONF) && !defined(HAVE_SYS_SYSLOG_H))
#  include <syslog.h>
#endif /* defined(HAVE_SYSLOG_H) || (!defined(AUTOCONF) && !defined(HAVE_SYS_SYSLOG_H)) */ 
#include <time.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include "extensions.h"
#include "pathnames.h"
#include "proto.h"

#if defined(AUTOBUF)
#include "buf_udp.h"
#include <poll.h>

#define INTERVAL_SEC 2
#define INTERVAL_USEC 0

#define UDP_NUMBER_OF_PACKAGES 10

#define UDP_PKT_SIZE 5000

struct itimerval val;
int all_lost = 0;
int udp_conn_setup = 0;
int udp_conn = 0;

void set_bufsize(int);
void print_bufsize(void);
void udp_timeout(int);
int measure_bufsize(int);
#endif /* defined(AUTOBUF) */

#include "tls_port.h"
extern char *protnames[];
#include "secutil.h" /* sets USE_SECURITY if it is needed */
#if defined(USE_SECURITY)

static int pbsz_command_issued = 0;
extern char *protnames[];
#endif /* defined(SECURITY) */ 

#if defined(USE_GSS)
#include "gssutil.h"

extern gss_info_t gss_info;
#endif /* defined(USE_GSS) */

extern int dolreplies;
#if !defined(INTERNAL_LS)
extern char ls_long[];
extern char ls_short[];
#endif /* !defined(INTERNAL_LS) */ 
extern struct SOCKSTORAGE data_dest;
extern struct SOCKSTORAGE his_addr;
extern int logged_in;
extern struct passwd *pw;
extern int anonymous;
extern int logging;
extern int log_commands;
extern int log_security;
extern int type;
extern int form;
extern int debug;
extern unsigned int timeout_idle;
extern unsigned int timeout_maxidle;
extern int pdata;
extern char hostname[], remotehost[], *remoteident;
extern char remoteaddr[];
extern char chroot_path[];
extern char guestpw[], authuser[];	/* added.  _H */
extern char proctitle[];
extern char *globerr;
extern int usedefault;
extern int transflag;
extern char tmpline[];
extern int data;
extern int errno;
extern char *home;
extern char wu_name[];
extern char wu_number[];
extern int allow_rest;

off_t restart_point;
int yyerrorcalled;

extern char *strunames[];
extern char *typenames[];
extern char *modenames[];
extern char *formnames[];
extern int restricted_user;	/* global flag indicating if user is restricted to home directory */

#if defined(AUTOBUF)
extern int TCPwindowsize;
#endif /* defined(AUTOBUF) */

#if defined(TRANSFER_COUNT)
extern off_t data_count_total;
extern off_t data_count_in;
extern off_t data_count_out;
extern off_t byte_count_total;
extern off_t byte_count_in;
extern off_t byte_count_out;
extern int file_count_total;
extern int xfer_count_total;
#endif /* defined(TRANSFER_COUNT) */ 

extern int retrieve_is_data;

#if defined(VIRTUAL)
extern int virtual_mode;
extern int virtual_ftpaccess;
extern char virtual_email[];
#endif /* defined(VIRTUAL) */ 

#if defined(IGNORE_NOOP)
static int alarm_running = 0;
#endif /* defined(IGNORE_NOOP) */ 

static unsigned short cliport = 0;
static struct in_addr cliaddr;
static int cmd_type;
static int cmd_form;
static int cmd_bytesz;
char cbuf[2048];
char *fromname;

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
#endif /* !defined(L_FORMAT)	- Autoconf detects this... */

#if defined(INET6)
extern int epsv_all;
int lport_error;
#endif /* defined(INET6) */ 

/* Debian linux bison fix: moved this up, added forward decls */

struct tab {
    char *name;
    short token;
    short state;
    /* non-zero if command is implemented, included in help messages if 1 */
    short implemented;
    char *help;
};

extern struct tab cmdtab[];
extern struct tab sitetab[];
extern struct tab optstab[];
extern char * feattab[];

static void toolong(int);
void help(struct tab *ctab, char *s);
struct tab *lookup(register struct tab *p, char *cmd);
void feat(char *tab[]);
/* int get_fact_string(char *ret_val, int size, const char *path, const char *facts); */
int yylex(void);

static char *nullstr = "(null)";
#define CHECKNULL(p) ((p) ? (p) : nullstr)

extern int pasv_allowed(const char *remoteaddr);
extern int port_allowed(const char *remoteaddr);
%}

%token
    A   B   C   E   F   I
    L   N   P   R   S   T

    SP  CRLF    COMMA   STRING  NUMBER

    USER    PASS    ACCT    REIN    QUIT    PORT
    PASV    TYPE    STRU    MODE    RETR    STOR
    APPE    MLFL    MAIL    MSND    MSOM    MSAM
    MRSQ    MRCP    ALLO    REST    RNFR    RNTO
    ABOR    DELE    CWD     LIST    NLST    SITE
    STAT    HELP    NOOP    MKD     RMD     PWD
    CDUP    STOU    SMNT    SYST    SIZE    MDTM
    EPRT    EPSV    LPRT    LPSV
    PROT    PBSZ    AUTH    ADAT    CCC

    MFF     MFCT    MFMT

    MLST    MLSD

    FEAT    OPTS

    CSID    CLNT

    UMASK   IDLE    CHMOD   GROUP   GPASS   NEWER
    MINFO   INDEX   EXEC    ALIAS   CDPATH  GROUPS
    CHECKMETHOD     CHECKSUM

    BUFSIZE BUFSIZEMEASURE SBUF

    LEXERR

%union {
    char *String;
    int Number;
}

%type <String>  STRING password pathname pathstring username method
%type <Number>  NUMBER byte_size check_login form_code 
%type <Number>  struct_code mode_code octal_number
%type <Number>  prot_code
%type <Number>  bufsize remote_mtu_size

%start  cmd_list

%%

cmd_list:	/* empty */
    | cmd_list cmd
		{
	    if (fromname) {
		free(fromname);
		fromname = NULL;
	    }
	    restart_point = 0;
	}
    | cmd_list rcmd
    ;

cmd: USER SP username CRLF
		{
#if defined(USE_SECURITY)
	    if ((SEC_CTRL_PROTECT_USER == get_control_policy()) && 
		(SEC_CTRL_TLS_PROTECTED != get_control_security()) &&
		(SEC_CTRL_GSS_PROTECTED != get_control_security())) {
		reply(503,"USER command not valid on insecure control connection");
		syslog(LOG_INFO, "unprotected USER");
	    } else
#endif /* defined(USE_SECURITY) */
	    user($3);
	    if (log_commands)
		syslog(LOG_INFO, "USER %s", $3);
	    free($3);
	}
    | PASS SP password CRLF
		{
	    if (log_commands) {
		if (anonymous)
		    syslog(LOG_INFO, "PASS %s", $3);
		else
		    syslog(LOG_INFO, "PASS password");
	    }

#if defined(USE_SECURITY)
	    if (SEC_AUTH_REQUIRE_STRONG == get_auth_policy()) {
		reply(500,"PASS command not valid");
		syslog(LOG_INFO, "disallowed PASS");
	    } else
#endif /* defined(USE_SECURITY) */
	    pass($3);
	    free($3);
	}
    | PORT check_login SP host_port CRLF
		{
	    if (log_commands)
		syslog(LOG_INFO, "PORT");
/* H* port fix, part B: admonish the twit.
   Also require login before PORT works */
	    if ($2) {
#if !defined(DISABLE_PORT)
#  if defined(INET6)
		if (epsv_all) {
		    reply(501, "PORT not allowed after EPSV ALL");
		    goto prt_done;
		}
#  endif /* defined(INET6) */ 
		if (((sock_cmp_inaddr(&his_addr, cliaddr) == 0)
		     || port_allowed(inet_ntoa(cliaddr)))
		    && (ntohs(cliport) >= IPPORT_RESERVED)) {
		    usedefault = 0;
		    if (pdata >= 0) {
			(void) CLOSE(pdata);
			pdata = -1;
		    }
		    SET_SOCK_FAMILY(data_dest, SOCK_FAMILY(his_addr));
		    SET_SOCK_PORT(data_dest, cliport);
		    SET_SOCK_ADDR4(data_dest, cliaddr);
		    reply(200, "PORT command successful.");
		}
		else {
#endif /* !defined(DISABLE_PORT) */ 
		    reply(502, "Illegal PORT Command");
prt_done:
		    usedefault = 1;
		    syslog(LOG_WARNING, "refused PORT %s,%d from %s",
			   inet_ntoa(cliaddr), ntohs(cliport), remoteident);
#if !defined(DISABLE_PORT)
		}
#endif /* !defined(DISABLE_PORT) */ 
	    }
	}
    | EPRT check_login SP STRING CRLF
		{
#if defined(INET6)
	    if (log_commands)
		syslog(LOG_INFO, "EPRT");
	    if ($2 && $4 != NULL) {
#  if !defined(DISABLE_PORT)
		char d, fmt[32], addr[INET6_ADDRSTRLEN + 1];
		int proto;
		unsigned short port;

		if (epsv_all) {
		    reply(501, "EPRT not allowed after EPSV ALL");
		    goto eprt_done;
		}
		d = *((char *)$4);
		if ((d < 33) || (d > 126)) {
		    reply(501, "Bad delimiter '%c' (%d).", d, d);
		    goto eprt_done;
		}
		if (d == '%')
		    snprintf(fmt, sizeof(fmt), 
			    "%%%1$c%%d%%%1$c%%%2$d[^%%%1$c]%%%1$c%%hu%%%1$c",
			    d, INET6_ADDRSTRLEN);
		else
		    snprintf(fmt, sizeof(fmt), 
			    "%1$c%%d%1$c%%%2$d[^%1$c]%1$c%%hu%1$c",
			    d, INET6_ADDRSTRLEN);

		if (sscanf((const char *)$4, fmt, &proto, addr, &port) != 3) {
		    reply(501, "EPRT bad format.");
		    goto eprt_done;
		}
		port = htons(port);

		switch (proto) {
		case 1:
		    SET_SOCK_FAMILY(data_dest, AF_INET);
		    break;
		case 2:
		    memset(&data_dest, 0, sizeof(struct sockaddr_in6));
		    SET_SOCK_FAMILY(data_dest, AF_INET6);
		    break;
		default:
		    reply(522, "Network protocol not supported, use (1,2)");
		    goto eprt_done;
		}
		if (inet_pton(SOCK_FAMILY(data_dest), addr, SOCK_ADDR(data_dest))
		    != 1) {
		    reply(501, "Bad address %s.", addr);
		    goto eprt_done;
		}

		if (((sock_cmp_addr(&his_addr, &data_dest) == 0)
		     || port_allowed(inet_stop(&data_dest)))
		    && (ntohs(port) >= IPPORT_RESERVED)) {
		    usedefault = 0;
		    if (pdata >= 0) {
			(void) close(pdata);
			pdata = -1;
		    }
		    SET_SOCK_PORT(data_dest, port);
		    SET_SOCK_SCOPE(data_dest, his_addr);
		    reply(200, "EPRT command successful.");
		}
		else {
#  endif /* !defined(DISABLE_PORT) */ 
		    reply(502, "Illegal EPRT Command");
eprt_done:
		    usedefault = 1;
		    syslog(LOG_WARNING, "refused EPRT %s from %s",
			   $4, remoteident);
#  if !defined(DISABLE_PORT)
		}
#  endif /* !defined(DISABLE_PORT) */ 
	    }
	    if ($4 != NULL)
		free($4);
#endif /* defined(INET6) */ 
	}
    | LPRT check_login SP host_lport CRLF
		{
#if defined(INET6)
	    if (log_commands)
		syslog(LOG_INFO, "LPRT");
	    if ($2) {
#  if !defined(DISABLE_PORT)
		if (lport_error)
		    goto lprt_done;
		if (((sock_cmp_addr(&his_addr, &data_dest) == 0)
		     || port_allowed(inet_stop(&data_dest)))
		    && (SOCK_PORT(data_dest) >= IPPORT_RESERVED)) {
		    usedefault = 0;
		    if (pdata >= 0) {
			(void) close(pdata);
			pdata = -1;
		    }
		    SET_SOCK_SCOPE(data_dest, his_addr);
		    reply(200, "LPRT command successful.");
		}
		else {
#  endif /* !defined(DISABLE_PORT) */ 
		    reply(502, "Illegal LPRT Command");
lprt_done:
		    usedefault = 1;
		    syslog(LOG_WARNING, "refused LPRT from %s", remoteident);
#  if !defined(DISABLE_PORT)
		}
#  endif /* !defined(DISABLE_PORT) */ 
	    }
#endif /* defined(INET6) */ 
	}
    | PASV check_login CRLF
		{
/* Require login for PASV, too.  This actually fixes a bug -- telnet to an
   unfixed wu-ftpd and type PASV first off, and it crashes! */
	    if (log_commands)
		syslog(LOG_INFO, "PASV");
	    if ($2) {
#if (defined (DISABLE_PORT) || !defined (DISABLE_PASV))
#  if defined(INET6)
		if (epsv_all)
		    reply(501, "PASV not allowed after EPSV ALL");
		else
#  endif /* defined(INET6) */ 
		    passive(TYPE_PASV, 0);
#else /* !((defined (DISABLE_PORT) || !defined (DISABLE_PASV))) */ 
		reply(502, "Illegal PASV Command");
#endif /* !((defined (DISABLE_PORT) || !defined (DISABLE_PASV))) */ 
	    }
	}
    | EPSV check_login CRLF
		{
#if defined(INET6)
	    if (log_commands)
		syslog(LOG_INFO, "EPSV");
	    if ($2)
#  if (defined (DISABLE_PORT) || !defined (DISABLE_PASV))
		passive(TYPE_EPSV, 0);
#  else /* !((defined (DISABLE_PORT) || !defined (DISABLE_PASV))) */ 
		reply(502, "Illegal EPSV Command");
#  endif /* !((defined (DISABLE_PORT) || !defined (DISABLE_PASV))) */ 
#endif /* defined(INET6) */ 
	}
    | EPSV check_login SP STRING CRLF
		{
#if defined(INET6)
	    if (log_commands)
		syslog(LOG_INFO, "EPSV");
	    if ($2 && $4 != NULL) {
#  if (defined (DISABLE_PORT) || !defined (DISABLE_PASV))
		if (strcasecmp((const char *)$4, "ALL") == 0) {
		    epsv_all = 1;
		    reply(200, "EPSV ALL command successful.");
		}
		else {
		    int af;
		    char *endp;

		    af = strtoul((char *)$4, &endp, 0);
		    if (*endp)
			reply(501, "'EPSV %s':" "command not understood.", $4);
		    else {
			/* Not allowed to specify address family 0 */
			if (af == 0)
			    af = -1;
			passive(TYPE_EPSV, af);
		    }
		}
#  else /* !((defined (DISABLE_PORT) || !defined (DISABLE_PASV))) */ 
		reply(502, "Illegal EPSV Command");
#  endif /* !((defined (DISABLE_PORT) || !defined (DISABLE_PASV))) */ 
	    }
	    if ($4 != NULL)
		free($4);
#endif /* defined(INET6) */ 
	}
    | LPSV check_login CRLF
		{
#if defined(INET6)
	    if (log_commands)
		syslog(LOG_INFO, "LPSV");
	    if ($2) {
#  if (defined (DISABLE_PORT) || !defined (DISABLE_PASV))
		if (epsv_all)
		    reply(501, "LPSV not allowed after EPSV ALL");
		else
		    passive(TYPE_LPSV, 0);
#  else /* !((defined (DISABLE_PORT) || !defined (DISABLE_PASV))) */ 
		reply(502, "Illegal LPSV Command");
#  endif /* !((defined (DISABLE_PORT) || !defined (DISABLE_PASV))) */ 
	    }
#endif /* defined(INET6) */ 
	}
    | TYPE check_login SP type_code CRLF
		{
	    if (log_commands)
		syslog(LOG_INFO, "TYPE %s", typenames[cmd_type]);
	    if ($2)
		switch (cmd_type) {

		case TYPE_A:
		    if (cmd_form == FORM_N) {
			reply(200, "Type set to A.");
			type = cmd_type;
			form = cmd_form;
		    }
		    else
			reply(504, "Form must be N.");
		    break;

		case TYPE_E:
		    reply(504, "Type E not implemented.");
		    break;

		case TYPE_I:
		    reply(200, "Type set to I.");
		    type = cmd_type;
		    break;

		case TYPE_L:
#if NBBY == 8
		    if (cmd_bytesz == 8) {
			reply(200,
			      "Type set to L (byte size 8).");
			type = cmd_type;
		    }
		    else
			reply(504, "Byte size must be 8.");
#else /* !(NBBY == 8) */ 
#  error UNIMPLEMENTED for NBBY != 8
#endif /* !(NBBY == 8) */ 
		}
	}
    | STRU check_login SP struct_code CRLF
		{
	    if (log_commands)
		syslog(LOG_INFO, "STRU %s", strunames[$4]);
	    if ($2)
		switch ($4) {

		case STRU_F:
		    reply(200, "STRU F ok.");
		    break;

		default:
		    reply(504, "Unimplemented STRU type.");
		}
	}
    | MODE check_login SP mode_code CRLF
		{
	    if (log_commands)
		syslog(LOG_INFO, "MODE %s", modenames[$4]);
	    if ($2)
		switch ($4) {

		case MODE_S:
		    reply(200, "MODE S ok.");
		    break;

		default:
		    reply(502, "Unimplemented MODE type.");
		}
	}
    | ALLO check_login SP NUMBER CRLF
		{
	    if (log_commands)
		syslog(LOG_INFO, "ALLO %d", $4);
	    if ($2)
		reply(202, "ALLO command ignored.");
	}
    | ALLO check_login SP NUMBER SP R SP NUMBER CRLF
		{
	    if (log_commands)
		syslog(LOG_INFO, "ALLO %d R %d", $4, $8);
	    if ($2)
		reply(202, "ALLO command ignored.");
	}
    | RETR check_login SP pathname CRLF
		{
	    if (log_commands)
		syslog(LOG_INFO, "RETR %s", CHECKNULL($4));
	    if ($2 && $4 != NULL && !restrict_check($4)) {
		retrieve_is_data = 1;
#if defined(USE_SECURITY)
		if (!is_data_connection_secure_enough($4,SEC_CMD_RETR)) {
		    reply(522,"Command invalid with this data PROT level");
		} else
#endif /* defined(USE_SECURITY) */ 
		retrieve((char *) NULL, $4);
	    }
	    if ($4 != NULL)
		free($4);
	}
    | STOR check_login SP pathname CRLF
		{
	    if (log_commands)
		syslog(LOG_INFO, "STOR %s", CHECKNULL($4));
	    if ($2 && $4 != NULL && !restrict_check($4))
#if defined(USE_SECURITY)
		if (!is_data_connection_secure_enough($4,SEC_CMD_STOR)) {
		    reply(522,"Command invalid with this data PROT level");
		} else
#endif /* defined(USE_SECURITY) */ 
		store($4, "w", 0);
	    if ($4 != NULL)
		free($4);
	}
    | APPE check_login SP pathname CRLF
		{
	    if (log_commands)
		syslog(LOG_INFO, "APPE %s", CHECKNULL($4));
	    if ($2 && $4 != NULL && !restrict_check($4))
#if defined(USE_SECURITY)
		if (!is_data_connection_secure_enough($4,SEC_CMD_APPE)) {
		    reply(522,"Command invalid with this data PROT level");
		} else
#endif /* defined(USE_SECURITY) */ 
		store($4, "a", 0);
	    if ($4 != NULL)
		free($4);
	}
    | NLST check_login CRLF
		{
	    if (log_commands)
		syslog(LOG_INFO, "NLST");
	    if ($2 && !restrict_check("."))
#if defined(USE_SECURITY)
		if (!is_data_connection_secure_enough("",SEC_CMD_NLST)) {
		    reply(522,"Command invalid with this data PROT level");
		} else
#endif /* defined(USE_SECURITY) */ 
		send_file_list("");
	}
    | NLST check_login SP STRING CRLF
		{
	    if (log_commands)
		syslog(LOG_INFO, "NLST %s", $4);
	    if ($2 && $4 && !restrict_check($4))
#if defined(USE_SECURITY)
		if (!is_data_connection_secure_enough($4,SEC_CMD_NLST)) {
		    reply(522,"Command invalid with this data PROT level");
		} else
#endif /* defined(USE_SECURITY) */ 
		send_file_list($4);
	    if ($4 != NULL)
		free($4);
	}
    | MLST check_login CRLF
		{
	    if(log_commands)
		syslog(LOG_INFO, "MLST");
	    if($2 && !restrict_check("."))
		mlst(NULL);
	}
    | MLST check_login SP pathname CRLF
		{
	    if (log_commands)
		syslog(LOG_INFO, "MLST %s", CHECKNULL($4));
	    if($2 && $4 && !restrict_check($4))
		mlst($4);
	    if($4 != NULL)
		free($4);
	}
    | MLSD check_login CRLF
		{
	    if(log_commands)
		syslog(LOG_INFO, "MLSD");
	    if($2 && !restrict_check(".")) {
		retrieve_is_data = 0;
		mlsd(NULL);
	    }
	}
    | MLSD check_login SP pathname CRLF
		{
	    if (log_commands)
		syslog(LOG_INFO, "MLSD %s", CHECKNULL($4));
	    if($2 && $4 && !restrict_list_check($4)) {
		retrieve_is_data = 0;
		mlsd($4);
	    }
	    if($4 != NULL)
		free($4);
	}
    | LIST check_login CRLF
		{
	    if (log_commands)
		syslog(LOG_INFO, "LIST");
	    if ($2 && !restrict_check(".")) {
		retrieve_is_data = 0;
#if defined(USE_SECURITY)
		if (!is_data_connection_secure_enough("",SEC_CMD_LIST)) {
		    reply(522,"Command invalid with this data PROT level");
		} else
#endif /* defined(USE_SECURITY) */ 
#if !defined(INTERNAL_LS)
		if (anonymous && dolreplies)
		    retrieve(ls_long, "");
		else
		    retrieve(ls_short, "");
#else /* !(!defined(INTERNAL_LS)) */ 
		ls(NULL, 0);
#endif /* !(!defined(INTERNAL_LS)) */ 
	    }
	}
    | LIST check_login SP pathname CRLF
		{
	    char *ls_args;
	    if (log_commands)
		syslog(LOG_INFO, "LIST %s", CHECKNULL($4));
	    if ($2 && $4 != NULL && !restrict_list_check($4)) {
		retrieve_is_data = 0;
#if defined(USE_SECURITY)
		if (!is_data_connection_secure_enough($4,SEC_CMD_LIST)) {
		    reply(522,"Command invalid with this data PROT level");
		} else
#endif /* defined(USE_SECURITY) */ 
#if !defined(INTERNAL_LS)
		ls_args = sanitise_ls_args($4);
		if (anonymous && dolreplies)
		    retrieve(ls_long, ls_args);
		else
		    retrieve(ls_short, ls_args);
		if (ls_args != NULL)
		    free(ls_args);
#else /* !(!defined(INTERNAL_LS)) */ 
		ls($4, 0);
#endif /* !(!defined(INTERNAL_LS)) */ 
	    }
	    if ($4 != NULL)
		free($4);
	}
    | STAT check_login SP pathname CRLF
		{
	    if (log_commands)
		syslog(LOG_INFO, "STAT %s", CHECKNULL($4));
	    if ($2 && $4 != NULL && !restrict_check($4))
		statfilecmd($4);
	    if ($4 != NULL)
		free($4);
	}
    | STAT check_login CRLF
		{
	    if (log_commands)
		syslog(LOG_INFO, "STAT");
	    if ($2)
		statcmd();
	}
    | DELE check_login SP pathname CRLF
		{
	    if (log_commands)
		syslog(LOG_INFO, "DELE %s", CHECKNULL($4));
	    if ($2 && $4 != NULL && !restrict_check($4))
		delete($4);
	    if ($4 != NULL)
		free($4);
	}
    | RNTO check_login SP pathname CRLF
		{
	    if (log_commands)
		syslog(LOG_INFO, "RNTO %s", CHECKNULL($4));
	    if ($2 && $4 && !restrict_check($4)) {
		if (fromname) {
		    renamecmd(fromname, $4);
		    free(fromname);
		    fromname = NULL;
		}
		else {
		    reply(503, "Bad sequence of commands.");
		}
	    }
	    if ($4)
		free($4);
	}
    | ABOR check_login CRLF
		{
	    if (log_commands)
		syslog(LOG_INFO, "ABOR");
	    if ($2)
		reply(226, "ABOR command successful.");
	}
    | CWD check_login CRLF
		{
	    if (log_commands)
		syslog(LOG_INFO, "CWD");
	    if ($2 && !restrict_check(home))
		cwd(home);
	}
    | CWD check_login SP pathname CRLF
		{
	    if (log_commands)
		syslog(LOG_INFO, "CWD %s", CHECKNULL($4));
	    if ($2 && $4 != NULL && !restrict_check($4))
		cwd($4);
	    if ($4 != NULL)
		free($4);
	}
    | HELP check_login CRLF
		{
	    if (log_commands)
		syslog(LOG_INFO, "HELP");
	    if ($2)
		help(cmdtab, (char *) NULL);
	}
    | HELP check_login SP STRING CRLF
		{
	    register char *cp = (char *) $4;

	    if (log_commands) 
		syslog(LOG_INFO, "HELP %s", $4);
	    if ($2) {
		if (strncasecmp(cp, "SITE", 4) == 0) {
		    cp = (char *) $4 + 4;
		    if (*cp == ' ')
			cp++;
		    if (*cp)
			help(sitetab, cp);
		    else
			help(sitetab, (char *) NULL);
		}
		else
		    help(cmdtab, $4);
	    }
	    if ($4 != NULL)
		free($4);
	}
    | FEAT check_login CRLF
		{
	    if (log_commands)
		syslog(LOG_INFO, "FEAT");
	    if ($2)
		feat(feattab);
	}
    | NOOP check_login CRLF
		{
	    if (log_commands) 
		syslog(LOG_INFO, "NOOP");
	    if ($2)
		reply(200, "NOOP command successful.");
	}
    | MKD check_login SP pathname CRLF
		{
	    if (log_commands)
		syslog(LOG_INFO, "MKD %s", CHECKNULL($4));
	    if ($2 && $4 != NULL && !restrict_check($4))
		makedir($4);
	    if ($4 != NULL)
		free($4);
	}
    | RMD check_login SP pathname CRLF
		{
	    if (log_commands)
		syslog(LOG_INFO, "RMD %s", CHECKNULL($4));
	    if ($2 && $4 != NULL && !restrict_check($4))
		removedir($4);
	    if ($4 != NULL)
		free($4);
	}
    | PWD check_login CRLF
		{
	    if (log_commands)
		syslog(LOG_INFO, "PWD");
	    if ($2)
		pwd();
	}
    | CDUP check_login CRLF
		{
	    if (log_commands)
		syslog(LOG_INFO, "CDUP");
	    if ($2) {
		if (!test_restriction(".."))
		    cwd("..");
		else
		    ack("CWD");
	    }
	}
    | SITE check_login SP HELP CRLF
		{
	    if (log_commands)
		syslog(LOG_INFO, "SITE HELP");
	    if ($2)
		help(sitetab, (char *) NULL);
	}
    | SITE check_login SP HELP SP STRING CRLF
		{
	    if (log_commands)
		syslog(LOG_INFO, "SITE HELP %s", $6);
	    if ($2)
		help(sitetab, $6);
	    if ($6 != NULL)
		free($6);
	}
    | SITE check_login SP UMASK CRLF
		{
	    mode_t oldmask;

	    if (log_commands)
		syslog(LOG_INFO, "SITE UMASK");
#if !defined(DISABLE_SITE_UMASK)
	    if ($2) {
		oldmask = umask(0);
		(void) umask(oldmask);
		reply(200, "Current UMASK is %03o", oldmask);
	    }
#else /* !(!defined(DISABLE_SITE_UMASK)) */ 
    reply(502, "%s command not implemented.", "SITE UMASK");
#endif /* !(!defined(DISABLE_SITE_UMASK)) */ 
	}
    | SITE check_login SP UMASK SP octal_number CRLF
		{
	    mode_t oldmask;
	    struct aclmember *entry = NULL;
	    int ok = (anonymous ? 0 : 1);

	    if (log_commands)
		syslog(LOG_INFO, "SITE UMASK %03o", $6);
#if !defined(DISABLE_SITE_UMASK)
	    if ($2) {
		/* check for umask permission */
		while (getaclentry("umask", &entry)) {
		    if (!ARG0)
			continue;
		    if (!ARG1) {
			if (!anonymous && ((*ARG0 == 'n') || (*ARG0 == 'N')))
			    ok = 0;
		    }
		    else if (type_match(ARG1)) {
			if (anonymous) {
			    if ((*ARG0 == 'y') || (*ARG0 == 'Y'))
				ok = 1;
			}
			else if ((*ARG0 == 'n') || (*ARG0 == 'N'))
			    ok = 0;
		    }
		}
		if (ok) {
		    if (($6 < 0) || ($6 > 0777)) {
			reply(501, "Bad UMASK value");
		    }
		    else {
			oldmask = umask((mode_t) $6);
			reply(200, "UMASK set to %03o (was %03o)", $6, oldmask);
		    }
		}
		else {
		    if (log_security) {
			if (anonymous)
			    syslog(LOG_NOTICE, "anonymous(%s) of %s tried to change umask",
				   guestpw, remoteident);
			else
			    syslog(LOG_NOTICE, "%s of %s tried to change umask",
				   pw->pw_name, remoteident);
		    }
		    reply(553, "Permission denied on server. (umask)");
		}
	    }
#else /* !(!defined(DISABLE_SITE_UMASK)) */ 
    reply(502, "%s command not implemented.", "SITE UMASK");
#endif /* !(!defined(DISABLE_SITE_UMASK)) */ 
	}
    | SITE check_login SP CHMOD SP octal_number SP pathname CRLF
		{
	    struct aclmember *entry = NULL;
	    int ok = (anonymous ? 0 : 1);

	    if (log_commands)
		syslog(LOG_INFO, "SITE CHMOD %03o %s", $6, CHECKNULL($8));
#if !defined(DISABLE_SITE_CHMOD)
	    if ($2 && $8) {
		/* check for chmod permission */
		while (getaclentry("chmod", &entry)) {
		    if (!ARG0)
			continue;
		    if (!ARG1) {
			if (!anonymous && ((*ARG0 == 'n') || (*ARG0 == 'N')))
			    ok = 0;
		    }
		    else if (type_match(ARG1)) {
			if (anonymous) {
			    if ((*ARG0 == 'y') || (*ARG0 == 'Y'))
				ok = 1;
			}
			else if ((*ARG0 == 'n') || (*ARG0 == 'N'))
			    ok = 0;
		    }
		}
		if (ok) {
#  if defined(UNRESTRICTED_CHMOD)
		    if (chmod($8, (mode_t) $6) < 0)
#  else /* !(defined(UNRESTRICTED_CHMOD)) */ 
		    if (($6 < 0) || ($6 > 0777))
			reply(501,
			    "CHMOD: Mode value must be between 0 and 0777");
		    else if (chmod($8, (mode_t) $6) < 0)
#  endif /* !(defined(UNRESTRICTED_CHMOD)) */ 
			perror_reply(550, $8);
		    else {
			char path[MAXPATHLEN];

			wu_realpath($8, path, chroot_path);

			if (log_security) {
			    if (anonymous) {
				syslog(LOG_NOTICE, "%s of %s changed permissions for %s", guestpw, remoteident, path);
			    }
			    else {
				syslog(LOG_NOTICE, "%s of %s changed permissions for %s", pw->pw_name,
				       remoteident, path);
			    }
			}
			reply(200, "CHMOD command successful.");
		    }
		}
		else {
		    char path[MAXPATHLEN];

		    wu_realpath($8, path, chroot_path);
		    if (log_security) {
			if (anonymous)
			    syslog(LOG_NOTICE, "anonymous(%s) of %s tried to change permissions on %s",
				   guestpw, remoteident, path);
			else
			    syslog(LOG_NOTICE, "%s of %s tried to change permissions on %s",
				   pw->pw_name, remoteident, path);
		    }
		    reply(553, "Permission denied on server. (chmod)");
		}
	    }
	    if ($8 != NULL)
		free($8);
#else /* !(!defined(DISABLE_SITE_CHMOD)) */ 
    reply(502, "%s command not implemented.", "SITE CHMOD");
#endif /* !(!defined(DISABLE_SITE_CHMOD)) */ 
	}
    | SITE check_login SP IDLE CRLF
		{
	    if (log_commands)
		syslog(LOG_INFO, "SITE IDLE");
#if !defined(DISABLE_SITE_IDLE)
	    if ($2)
		reply(200,
		      "Current IDLE time limit is %d seconds; max %d",
		      timeout_idle, timeout_maxidle);
#else /* !(!defined(DISABLE_SITE_IDLE)) */ 
    reply(502, "%s command not implemented.", "SITE IDLE");
#endif /* !(!defined(DISABLE_SITE_IDLE)) */ 
	}
    | SITE check_login SP IDLE SP NUMBER CRLF
		{
	    if (log_commands)
		syslog(LOG_INFO, "SITE IDLE %d", $6);
#if !defined(DISABLE_SITE_IDLE)
	    if ($2) {
		if ($6 < 30 || $6 > timeout_maxidle) {
		    reply(501,
		      "Maximum IDLE time must be between 30 and %d seconds",
			  timeout_maxidle);
		}
		else {
		    timeout_idle = $6;
		    reply(200, "Maximum IDLE time set to %d seconds", timeout_idle);
		}
	    }
#else /* !(!defined(DISABLE_SITE_IDLE)) */ 
    reply(502, "%s command not implemented.", "SITE IDLE");
#endif /* !(!defined(DISABLE_SITE_IDLE)) */ 
	}
    | SITE check_login SP GROUP SP username CRLF
		{
#if !defined(NO_PRIVATE)
	    if (log_commands)
		syslog(LOG_INFO, "SITE GROUP %s", $6);
	    if ($2 && $6)
		priv_group($6);
	    free($6);
#endif /* !defined(NO_PRIVATE) */ 
	}
    | SITE check_login SP GPASS SP password CRLF
		{
#if !defined(NO_PRIVATE)
	    if (log_commands)
		syslog(LOG_INFO, "SITE GPASS password");
	    if ($2 && $6)
		priv_gpass($6);
	    free($6);
#endif /* !defined(NO_PRIVATE) */ 
	}
    | SITE check_login SP GPASS CRLF
		{
#if !defined(NO_PRIVATE)
	    if (log_commands)
		syslog(LOG_INFO, "SITE GPASS");
	    if ($2)
		priv_gpass(NULL);
#endif /* !defined(NO_PRIVATE) */ 
	}
    | SITE check_login SP NEWER SP STRING CRLF
		{
	    if (log_commands)
		syslog(LOG_INFO, "SITE NEWER %s", $6);
#if defined(SITE_NEWER)
	    if ($2 && $6 && !restrict_check("."))
		newer($6, ".", 0);
#else /* !(defined(SITE_NEWER)) */ 
	    reply(502, "Command no longer honored by this server");
#endif /* !(defined(SITE_NEWER)) */ 
	    free($6);
	}
    | SITE check_login SP NEWER SP STRING SP pathname CRLF
		{
	    if (log_commands)
		syslog(LOG_INFO, "SITE NEWER %s %s", $6,
		       CHECKNULL($8));
#if defined(SITE_NEWER)
	    if ($2 && $6 && $8 && !restrict_check($8))
		newer($6, $8, 0);
#else /* !(defined(SITE_NEWER)) */ 
	    reply(502, "Command no longer honored by this server");
#endif /* !(defined(SITE_NEWER)) */ 
	    free($6);
	    if ($8)
		free($8);
	}
    | SITE check_login SP MINFO SP STRING CRLF
		{
	    if (log_commands)
		syslog(LOG_INFO, "SITE MINFO %s", $6);
#if defined(SITE_NEWER)
	    if ($2 && $6 && !restrict_check("."))
		newer($6, ".", 1);
#else /* !(defined(SITE_NEWER)) */ 
	    reply(502, "Command no longer honored by this server");
#endif /* !(defined(SITE_NEWER)) */ 
	    free($6);
	}
    | SITE check_login SP MINFO SP STRING SP pathname CRLF
		{
	    if (log_commands)
		syslog(LOG_INFO, "SITE MINFO %s %s", $6,
		       CHECKNULL($8));
#if defined(SITE_NEWER)
	    if ($2 && $6 && $8 && !restrict_check($8))
		newer($6, $8, 1);
#else /* !(defined(SITE_NEWER)) */ 
	    reply(502, "Command no longer honored by this server");
#endif /* !(defined(SITE_NEWER)) */ 
	    free($6);
	    if ($8)
		free($8);
	}
    | SITE check_login SP INDEX SP STRING CRLF
		{
#if defined(ENABLE_SITE_EXEC)
	    /* this is just for backward compatibility since we
	     * thought of INDEX before we thought of EXEC
	     */
	    if (!restricted_user && $2 != 0 && $6 != NULL) {
		char buf[MAXPATHLEN];
		if (strlen($6) + 7 <= sizeof(buf)) {
		    snprintf(buf, sizeof(buf), "index %s", (char *) $6);
		    (void) site_exec(buf);
		}
	    }
	    else
		reply(553, "Permission denied on server.");
	    if ($6 != NULL)
		free($6);
#else /* !(defined(ENABLE_SITE_EXEC)) */ 
	  if (log_commands)
		  syslog(LOG_INFO, "REFUSED SITE INDEX %s", $6);
    reply(502, "%s command not implemented.", "SITE INDEX");
#endif /* !(defined(ENABLE_SITE_EXEC)) */ 
	}
    | SITE check_login SP EXEC SP STRING CRLF
		{
#if defined(ENABLE_SITE_EXEC)
	    if (!restricted_user && $2 != 0 && $6 != NULL) {
		(void) site_exec((char *) $6);
	    }
	    else
		reply(553, "Permission denied on server.");
	    if ($6 != NULL)
		free($6);
#else /* !(defined(ENABLE_SITE_EXEC)) */ 
	  if (log_commands)
		  syslog(LOG_INFO, "REFUSED SITE EXEC %s", $6);
    reply(502, "%s command not implemented.", "SITE EXEC");
#endif /* !(defined(ENABLE_SITE_EXEC)) */ 
	}

    | STOU check_login CRLF
		{
	    if (log_commands)
		syslog(LOG_INFO, "STOU");
	    if ($2 && !restrict_check("."))
#if defined(USE_SECURITY)
		if (!is_data_connection_secure_enough("",SEC_CMD_STOU)) {
		    reply(522,"Command invalid with this data PROT level");
		} else
#endif /* defined(USE_SECURITY) */ 
		store("file", "w", 1);
	}
    | STOU check_login SP pathname CRLF
		{
	    if (log_commands)
		syslog(LOG_INFO, "STOU %s", CHECKNULL($4));
	    if ($2 && $4 && !restrict_check($4))
#if defined(USE_SECURITY)
		if (!is_data_connection_secure_enough($4,SEC_CMD_STOU)) {
		    reply(522,"Command invalid with this data PROT level");
		} else
#endif /* defined(USE_SECURITY) */ 
		store($4, "w", 1);
	    if ($4 != NULL)
		free($4);
	}
    | SYST check_login CRLF
		{
	    if (log_commands)
		syslog(LOG_INFO, "SYST");
	    if ($2)
#if defined(BSD)
		reply(215, "UNIX Type: L%d Version: BSD-%d", NBBY, BSD);
#  elif defined(SOLARIS_2)
		reply(215, "UNIX Type: L%d Version: SUNOS", NBBY);
#  elif defined(unix) || defined(__unix__)
		reply(215, "UNIX Type: L%d", NBBY);
#else /* !(defined(BSD)) */ 
		reply(215, "UNKNOWN Type: L%d", NBBY);
#endif /* !(defined(BSD)) */ 
	}

	/*
	 * SIZE is not in RFC959, but Postel has blessed it and
	 * it will be in the updated RFC.
	 *
	 * Return size of file in a format suitable for
	 * using with RESTART (we just count bytes).
	 */
    | SIZE check_login SP pathname CRLF
		{
	    if (log_commands)
		syslog(LOG_INFO, "SIZE %s", CHECKNULL($4));
	    if ($2 && $4 && !restrict_check($4)) {
		sizecmd($4);
	    }
	    if ($4 != NULL)
		free($4);
	}

	/*
	 * MDTM is not in RFC959, but Postel has blessed it and
	 * it will be in the updated RFC.
	 *
	 * Return modification time of file as an ISO 3307
	 * style time. E.g. YYYYMMDDHHMMSS or YYYYMMDDHHMMSS.xxx
	 * where xxx is the fractional second (of any precision,
	 * not necessarily 3 digits)
	 */
    | MDTM check_login SP pathname CRLF
		{
	    if (log_commands)
		syslog(LOG_INFO, "MDTM %s", CHECKNULL($4));
	    if ($2 && $4 && !restrict_check($4)) {
		struct stat stbuf;

		if (stat($4, &stbuf) < 0)
		    perror_reply(550, $4);
		else if ((stbuf.st_mode & S_IFMT) != S_IFREG) {
		    reply(550, "%s: not a plain file.",
			  $4);
		}
		else {
		    register struct tm *t;
		    t = gmtime(&stbuf.st_mtime);
		    reply(213,
			  "%04d%02d%02d%02d%02d%02d",
			  t->tm_year + 1900, t->tm_mon + 1, t->tm_mday,
			  t->tm_hour, t->tm_min, t->tm_sec);
		}
	    }
	    if ($4 != NULL)
		free($4);
	}
    | OPTS check_login opts CRLF
		{
	    if (log_commands)
		syslog(LOG_INFO, "OPTS");
	    reply(200, "OPTS successful.");
	}
    /* FIXME - command stubs MFF, MFCT, MFMT */
    | MFF check_login CRLF
		{
	    if (log_commands)
		syslog(LOG_INFO, "MFF");
	    reply(502, "Command not implemented.");
	}
    | MFCT check_login SP NUMBER SP pathname CRLF
		{
	    if (log_commands)
		syslog(LOG_INFO, "MFCT");
	    reply(502, "Command not implemented.");
	}
    | MFMT check_login SP NUMBER SP pathname CRLF
		{
	    if (log_commands)
		syslog(LOG_INFO, "MFMT");
	    reply(502, "Command not implemented.");
	}
    /* FIXME make CSID customisable */
    | CSID check_login SP STRING CRLF
		{
	    if (log_commands)
		syslog(LOG_INFO, "CSID %s", $4);
	    if ($2 && $4 && !restrict_check($4))
		reply(200, "CaseSensitive=1;Version=%s;Name=%s;", wu_number, wu_name);
	    if ($4 != NULL)
		free($4);
	}
    | CLNT check_login SP STRING CRLF
		{
	    if (log_commands)
		syslog(LOG_INFO, "CLNT %s", $4);
	    if ($2 && $4 && !restrict_check($4))
		reply(200, "CaseSensitive=1;Version=%s;Name=%s;", wu_number, wu_name);
	    if ($4 != NULL)
		free($4);
	}
    | QUIT CRLF
		{
	    if (log_commands)
		syslog(LOG_INFO, "QUIT");
	    {
		struct aclmember *entry = NULL;
		int signoff_option = 0;
		if (getaclentry("signoff", &entry) && ARG0) {
		    if (!strcasecmp(ARG0, "full"))
			signoff_option = 0;
		    else if (!strcasecmp(ARG0, "text") && ARG1)
			signoff_option = 3;
		    else if (!strcasecmp(ARG0, "terse"))
			signoff_option = 2;
		    else if (!strcasecmp(ARG0, "brief"))
			signoff_option = 1;
		}
		switch (signoff_option) {
		    default:
#if defined(TRANSFER_COUNT)
			if (logged_in) {
			    lreply(221, "You have transferred %" L_FORMAT " bytes in %d files.", data_count_total, file_count_total);
			    lreply(221, "Total traffic for this session was %" L_FORMAT " bytes in %d transfers.", byte_count_total, xfer_count_total);
			}
#endif /* defined(TRANSFER_COUNT) */ 
		    case 1:
			if (logged_in)
			    lreply(221, "Thank you for using the FTP service on %s.", hostname);
		    case 2:
			reply(221, "Goodbye.");
			break;
		    case 3: {
			char output_text[1025];
			int which;

			output_text[0] = '\0';
			for (which = 1; (which < MAXARGS) && ARG[which];
			     which++) {
			    if (which > 1)
				strlcat(output_text, " ", sizeof(output_text));
			    strlcat(output_text, ARG[which],
				    sizeof(output_text));
			}
			reply(221, "%s", output_text);
			break;
		    }
		}
		dologout(0);
	    }
	}
    | SITE check_login SP ALIAS CRLF
		{
	    if (log_commands)
		syslog(LOG_INFO, "SITE ALIAS");
#if !defined(DISABLE_SITE_ALIAS)
	    if ($2)
		alias((char *) NULL);
#else /* !(!defined(DISABLE_SITE_ALIAS)) */ 
    reply(502, "%s command not implemented.", "SITE ALIAS");
#endif /* !(!defined(DISABLE_SITE_ALIAS)) */ 
	}
    | SITE check_login SP ALIAS SP STRING CRLF
		{
	    if (log_commands)
		syslog(LOG_INFO, "SITE ALIAS %s", $6);
#if !defined(DISABLE_SITE_ALIAS)
	    if ($2)
		alias($6);
	    if ($6 != NULL)
		free($6);
#else /* !(!defined(DISABLE_SITE_ALIAS)) */ 
    reply(502, "%s command not implemented.", "SITE ALIAS");
#endif /* !(!defined(DISABLE_SITE_ALIAS)) */ 
	}
    | SITE check_login SP GROUPS CRLF
		{
	    if (log_commands)
		syslog(LOG_INFO, "SITE GROUPS");
#if !defined(DISABLE_SITE_GROUPS)
	    if ($2)
		print_groups();
#else /* !(!defined(DISABLE_SITE_GROUPS)) */ 
    reply(502, "%s command not implemented.", "SITE GROUPS");
#endif /* !(!defined(DISABLE_SITE_GROUPS)) */ 
	}
    | SITE check_login SP CDPATH CRLF
		{
	    if (log_commands)
		syslog(LOG_INFO, "SITE CDPATH");
#if !defined(DISABLE_SITE_CDPATH)
	    if ($2)
		cdpath();
#else /* !(!defined(DISABLE_SITE_CDPATH)) */ 
    reply(502, "%s command not implemented.", "SITE CDPATH");
#endif /* !(!defined(DISABLE_SITE_CDPATH)) */ 
	}
    | SITE check_login SP CHECKMETHOD SP method CRLF
		{
	    if (log_commands)
		syslog(LOG_INFO, "SITE CHECKMETHOD %s", CHECKNULL($6));
#if !defined(DISABLE_SITE_CHECKMETHOD)
	    if (($2) && ($6 != NULL))
		SetCheckMethod($6);
	    if ($6 != NULL)
		free($6);
#else /* !(!defined(DISABLE_SITE_CHECKMETHOD)) */ 
    reply(502, "%s command not implemented.", "SITE CHECKMETHOD");
#endif /* !(!defined(DISABLE_SITE_CHECKMETHOD)) */ 
	}
    | SITE check_login SP CHECKMETHOD CRLF
		{
	    if (log_commands)
		syslog(LOG_INFO, "SITE CHECKMETHOD");
#if !defined(DISABLE_SITE_CHECKMETHOD)
	    if ($2)
		ShowCheckMethod();
#else /* !(!defined(DISABLE_SITE_CHECKMETHOD)) */ 
    reply(502, "%s command not implemented.", "SITE CHECKMETHOD");
#endif /* !(!defined(DISABLE_SITE_CHECKMETHOD)) */ 
	}
    | SITE check_login SP CHECKSUM SP pathname CRLF
		{
	    if (log_commands)
		syslog(LOG_INFO, "SITE CHECKSUM %s", CHECKNULL($6));
#if !defined(DISABLE_SITE_CHECKSUM)
	    if (($2) && ($6 != NULL) && (!restrict_check($6)))
		CheckSum($6);
	    if ($6 != NULL)
		free($6);
#else /* !(!defined(DISABLE_SITE_CHECKSUM)) */ 
    reply(502, "%s command not implemented.", "SITE CHECKSUM");
#endif /* !(!defined(DISABLE_SITE_CHECKSUM)) */ 
	}
    | SITE check_login SP CHECKSUM CRLF
		{
	    if (log_commands)
		syslog(LOG_INFO, "SITE CHECKSUM");
#if !defined(DISABLE_SITE_CHECKSUM)
	    if ($2)
		CheckSumLastFile();
#else /* !(!defined(DISABLE_SITE_CHECKSUM)) */ 
    reply(502, "%s command not implemented.", "SITE CHECKSUM");
#endif /* !(!defined(DISABLE_SITE_CHECKSUM)) */ 
	}
    | SITE check_login SP BUFSIZE CRLF
		{
#if defined(AUTOBUF)
	    if (log_commands)
		syslog(LOG_INFO, "SITE BUFSIZE");
	    print_bufsize();
#else /* !(defined(AUTOBUF)) */
	    reply(500,"SITE BUFSIZE command not supported.");
#endif /* defined(AUTOBUF) */
	}
    | SITE check_login SP BUFSIZEMEASURE SP remote_mtu_size CRLF
		{
#if defined(AUTOBUF)
	    int size = $6;
	    if (log_commands)
		syslog(LOG_INFO, "SITE BUFSIZEMEASURE");
	    measure_bufsize(size);
#else /* !(defined(AUTOBUF)) */
	    reply(500,"SITE BUFSIZEMEASURE command not supported.");
#endif /* defined(AUTOBUF) */
	}
    | SITE check_login SP BUFSIZE SP bufsize CRLF
		{
#if defined(AUTOBUF)
	    int size = $6;
	    if (log_commands)
		syslog(LOG_INFO, "SITE BUFSIZE %d", size);
	    set_bufsize(size);
#else /* !(defined(AUTOBUF)) */
	    reply(500,"SITE BUFSIZE command not supported.");
#endif /* defined(AUTOBUF) */
	}
    | SBUF check_login CRLF
		{
#if defined(AUTOBUF)
	    if (log_commands)
		syslog(LOG_INFO, "SBUF");
	    print_bufsize();
#else /* !(defined(AUTOBUF)) */
	    reply(500,"SBUF command not supported.");
#endif /* defined(AUTOBUF) */
	}
    | SBUF check_login SP bufsize CRLF
		{
#if defined(AUTOBUF)
	    int size = $4;
	    if (log_commands)
		syslog(LOG_INFO, "SBUF %d", size);
	    set_bufsize(size);
#else /* !(defined(AUTOBUF)) */
	    reply(500,"SBUF command not supported.");
#endif /* defined(AUTOBUF) */
	}
    | PBSZ SP STRING CRLF
		{
#if defined(USE_SECURITY)
	    if (log_commands)
		syslog(LOG_INFO, "PBSZ %s", $3);

	    if ((SEC_CTRL_TLS_PROTECTED != get_control_security()) &&
		(SEC_CTRL_GSS_PROTECTED != get_control_security())) {
		reply(503, "PBSZ only valid on secure control channel");
	    }
#if defined(USE_TLS)
	    if (SEC_CTRL_TLS_PROTECTED == get_control_security()) {
		reply(200, "PBSZ=0");
		pbsz_command_issued = 1;
	    }
#endif /* defined(USE_TLS) */
#if defined(USE_GSS)
	    if (SEC_CTRL_GSS_PROTECTED == get_control_security()) {
		/* the 'gss_setpbsz' routine handles the reply code */
		(void) gss_setpbsz((char *)$3);
		pbsz_command_issued = 1;
	    }
#endif /* defined(USE_GSS) */
#else /* !(defined(USE_SECURITY)) */
	    reply(500,"PBSZ command not supported.");
#endif /* (defined(USE_SECURITY)) */
	    if ($3 != NULL)
		free((char *)$3);
	}
    | AUTH SP STRING CRLF
		{
#if defined(USE_SECURITY)
	    register char *cp = (char *) $3;
	    if (SEC_CTRL_NOT_YET_PROTECTED != get_control_security()) {
		reply(534,"AUTH command not allowed at this time.");
	    } else {
		if (log_commands)
		    syslog(LOG_INFO, "AUTH %s", $3);
		/* convert to UPPER case  as per RFC 2228 */
		while (*cp) {
		    *cp = toupper(*cp);
		    cp++;
		}
#if defined(USE_TLS)
		if ((sec_check_mechanism(SEC_MECHANISM_TLS)) && 
		    ((!strncmp((char *) $3,"TLS",4)) ||
		    (!strncmp((char *) $3,"TLS-C",5)))) {
		    reply(234, "AUTH TLS OK.");
		    if (tls_accept_ctrl(fileno(stdin))) {
			/* exit if we fail */
			reply(421, "Failed TLS negotiation on control channel, disconnected");
			syslog(LOG_ERR, "Failed TLS negotiation on control channel, disconnected.");
			dologout(1);
		    }
		    set_control_security(SEC_CTRL_TLS_PROTECTED);
		    set_data_prot_level('C');
		    set_data_prot_mechanism(SEC_DATA_MECHANISM_PLAIN);

		} else if ((sec_check_mechanism(SEC_MECHANISM_TLS)) &&
			   ((!strncmp((char *) $3,"SSL",4)) ||
			    (!strncmp((char *) $3,"TLS-P",5)))) {
		    if (tls_hack_allow_auth_ssl()) {
			reply((tls_hack_bad_auth_ssl_reply()) ? 334 : 234, 
			    "AUTH SSL OK.");
			if (tls_accept_ctrl(fileno(stdin))) {
			    /* exit if we fail */
			    reply(421, "Failed TLS negotiation on control channel, disconnected");
			    syslog(LOG_ERR, "Failed TLS negotiation on control channel, disconnected.");
			    dologout(1);
			}
			set_control_security(SEC_CTRL_TLS_PROTECTED);
			set_data_prot_level('P');
			set_data_prot_mechanism(SEC_DATA_MECHANISM_TLS);
		    } else {
			reply(504, "AUTH SSL not supported.");
		    }
		} else
#endif /* defined(USE_TLS) */
#if defined(USE_GSS)
		if (!strncmp((char *) $3, "GSSAPI", 6) &&
		    sec_check_mechanism(SEC_MECHANISM_GSS)) {
		    set_control_security(SEC_CTRL_GSS_PROTECTED);
		    reply(334, "Using AUTH type %s; ADAT must follow",
			(char *)$3);
		} else
#endif /* defined(USE_GSS) */
		{
		     reply(504,"AUTH %s not supported.", $3);
		}
	     }
#else /* !(defined(USE_SECURITY)) */ 
	    reply(500,"AUTH command not supported.");
#endif /* !(defined(USE_SECURITY)) */ 
	    if ($3 != NULL)
		free((char *)$3);
	}
    | PROT SP prot_code CRLF
		{
#if defined(USE_SECURITY)
	    if (log_commands)
		syslog(LOG_INFO, "PROT %s", protnames[$3]);

	    if ((SEC_CTRL_NOT_YET_PROTECTED == get_control_security()) ||
		(SEC_CTRL_CLEARED == get_control_security())) {
		reply(503, "PROT only valid on secure control channel");
	    } else {
		if (!pbsz_command_issued) {
		    reply(503, "PROT command not valid before PBSZ.");
		} else {
		    switch ($3) {

		    case PROT_P:
			reply(200, "PROT P ok.");
			set_data_prot_level('P');
#if defined(USE_TLS)
			if (SEC_CTRL_TLS_PROTECTED == get_control_security()) {
			    set_data_prot_mechanism(SEC_DATA_MECHANISM_TLS);
			}
#endif /* defined(USE_TLS) */
#if defined(USE_GSS)
			if (SEC_CTRL_GSS_PROTECTED == get_control_security()) {
			    set_data_prot_mechanism(SEC_DATA_MECHANISM_GSS);
			    gss_info.data_prot = PROT_P;
			}
#endif /* defined(USE_GSS) */
		    break;

		    case PROT_C:
			reply(200, "PROT C ok.");
			set_data_prot_level('C');
#if defined(USE_TLS)
			if (SEC_CTRL_TLS_PROTECTED == get_control_security()) {
			    set_data_prot_mechanism(SEC_DATA_MECHANISM_PLAIN);
			}
#endif /* defined(USE_TLS) */
#if defined(USE_GSS)
			if (SEC_CTRL_GSS_PROTECTED == get_control_security()) {
			    set_data_prot_mechanism(SEC_DATA_MECHANISM_PLAIN);
			    gss_info.data_prot = PROT_C;
			}
#endif /* defined(USE_GSS) */
			break;

		    case PROT_E:
			reply(536, "PROT E unsupported");
			break;

		    case PROT_S:
#if defined(USE_GSS)
			if (SEC_CTRL_GSS_PROTECTED == get_control_security()) {
			    reply(200, "PROT S ok.");
			    set_data_prot_level('S');
			    set_data_prot_mechanism(SEC_DATA_MECHANISM_GSS);
			    gss_info.data_prot = PROT_S;
			}
#endif /* defined(USE_GSS) */
#if defined(USE_TLS)
			if (SEC_CTRL_TLS_PROTECTED == get_control_security())
			    reply(536, "PROT S unsupported with TLS");
#endif /* defined(USE_TLS) */
			if ((SEC_CTRL_NOT_YET_PROTECTED == 
						get_control_security()) ||
			    (SEC_CTRL_CLEARED == get_control_security()))
			    reply(503, "PROT S unsupported at this time");
			break;

		    default:
			reply(504, "Invalid PROT type.");
		    } /* switch */
#if defined(USE_GSS)
		if (sec_check_mechanism(SEC_MECHANISM_GSS))
		    gss_adjust_buflen();
#endif /* defined(USE_GSS) */
		} /* else ... switch */
	    } /* else if (pbsz_command_issued) */
#else /* !(defined(USE_SECURITY)) */ 
	    reply(500,"PROT command not supported.");
#endif /* defined(USE_SECURITY) */ 
	}
    | ADAT SP STRING CRLF
		{
#if defined(USE_GSS)
	    if (log_commands)
		syslog(LOG_INFO, "ADAT %s", $3);

	    if (SEC_CTRL_GSS_PROTECTED == get_control_security())
		gss_adat((char *)$3);
	    else
		reply(503, "ADAT command not valid at this time");
#else /* !defined(USE_GSS) */
	    reply(500, "ADAT command not supported");
#endif /* defined(USE_GSS) */
	    if ($3 != NULL)
		free((char *)$3);
	}
    | CCC CRLF
		{
#if defined(USE_SECURITY)
	    if (log_commands)
		syslog(LOG_INFO, "CCC");

	    if ((SEC_CTRL_NOT_YET_PROTECTED == get_control_security()) ||
		(SEC_CTRL_CLEARED == get_control_security()))
		reply(533,"Command protection level denied for policy reasons.");

#if defined(USE_GSS)
	    if (SEC_CTRL_GSS_PROTECTED == get_control_security())
		ccc();
#endif /* defined(USE_GSS) */

#if defined(USE_TLS)
	    if (SEC_CTRL_TLS_PROTECTED == get_control_security()) {
		if (SEC_CCC_DISALLOWED == get_ccc_policy()) {
		    reply(534,"Request denied for policy reasons.");
		} else {
		    /* the 200 reply must be sent on the protected channel */
		    reply(200,"Command Channel Cleared.");
		    tls_ccc();
		    set_control_security(SEC_CTRL_CLEARED);
		}
	    }
#endif /* defined(USE_TLS) */
#else /* defined(USE_SECURITY) */
	    reply(500,"CCC command not supported."); 
#endif /* defined(USE_SECURITY) */
	}
    | error CRLF
		{
	    yyerrok;
	}
    ;

rcmd: RNFR check_login SP pathname CRLF
		{

	    if (log_commands)
		syslog(LOG_INFO, "RNFR %s", CHECKNULL($4));
	    if ($2)
		restart_point = 0;
	    if (fromname) {
		free(fromname);
		fromname = NULL;
	    }
	    if ($2 && $4 && !restrict_check($4)) {
		fromname = renamefrom($4);
	    }
	    if (fromname == NULL && $4)
		free($4);
	}
    | REST check_login SP STRING CRLF
		{
	if (allow_rest ) {
	    if (log_commands)
		syslog(LOG_INFO, "REST %s", CHECKNULL($4));
	    if ($2 && $4 != NULL) {
		char *endp;

		if (fromname) {
		    free(fromname);
		    fromname = NULL;
		}
		errno = 0;
#if _FILE_OFFSET_BITS == 64
		restart_point = strtoll($4, &endp, 10);
#else /* !(_FILE_OFFSET_BITS == 64) */ 
		restart_point = strtol($4, &endp, 10);
#endif /* !(_FILE_OFFSET_BITS == 64) */ 
		if ((errno == 0) && (restart_point >= 0) && (*endp == '\0')) {
		    reply(350, "Restarting at %" L_FORMAT
			  ". Send STORE or RETRIEVE to initiate transfer.",
			  restart_point);
		}
		else {
		    restart_point = 0;
		    reply(501, "Bad value for REST: %s", $4);
		}
	    }
	    if ($4 != NULL)
		free($4);
	} else {
	    reply(502, "REST has been disabled.");
	}
     }
    ;

username: STRING
    ;

password: /* empty */
		{
	    $$ = (char *) malloc(1);
	    $$[0] = '\0';
	}
    | STRING
    ;

byte_size: NUMBER
    ;

opts: SP MLST SP STRING
		{
	mlsx_options($4);
	}
    | SP MLST
		{
	mlsx_options(NULL);
	}
    ;

host_port: NUMBER COMMA NUMBER COMMA NUMBER COMMA NUMBER COMMA NUMBER COMMA NUMBER
		{
	    register char *a, *p;

	    a = (char *) &cliaddr;
	    a[0] = $1;
	    a[1] = $3;
	    a[2] = $5;
	    a[3] = $7;
	    p = (char *) &cliport;
	    p[0] = $9;
	    p[1] = $11;
	}
    ;

host_lport: NUMBER COMMA NUMBER COMMA
	NUMBER COMMA NUMBER COMMA NUMBER COMMA NUMBER COMMA
	NUMBER COMMA NUMBER COMMA NUMBER COMMA NUMBER COMMA
	NUMBER COMMA NUMBER COMMA NUMBER COMMA NUMBER COMMA
	NUMBER COMMA NUMBER COMMA NUMBER COMMA NUMBER COMMA
	NUMBER COMMA NUMBER COMMA NUMBER
		{
#if defined(INET6)
	    char *a, *p;
	    struct sockaddr_in6 *data_dest_sin6;

	    lport_error = 0;
	    if (epsv_all) {
		reply(501, "LPRT not allowed after EPSV ALL");
		lport_error = 1;
		goto lport_done6;
	    }
	    if ($1 != 6) {
		reply(521, "Supported address families are (4, 6)");
		lport_error = 1;
		goto lport_done6;
	    }
	    if (($3 != 16) || ($37 != 2)) {
		reply(501, "Bad length.");
		lport_error = 1;
		goto lport_done6;
	    }
	    memset(&data_dest, 0, sizeof(struct sockaddr_in6));
	    data_dest_sin6 = (struct sockaddr_in6 *) &data_dest;
	    data_dest_sin6->sin6_family = AF_INET6;
	    a = (char *)&data_dest_sin6->sin6_addr;
	    a[0]  = $5;  a[1]  = $7;  a[2]  = $9;   a[3] = $11;
	    a[4]  = $13; a[5]  = $15; a[6]  = $17;  a[7] = $19;
	    a[8]  = $21; a[9]  = $23; a[10] = $25; a[11] = $27;
	    a[12] = $29; a[13] = $31; a[14] = $33; a[15] = $35;
	    p = (char *)&data_dest_sin6->sin6_port;
	    p[0] = $39; p[1] = $41;
lport_done6:;
#endif /* defined(INET6) */ 
	}
    | NUMBER COMMA NUMBER COMMA
	NUMBER COMMA NUMBER COMMA NUMBER COMMA NUMBER COMMA
	NUMBER COMMA NUMBER COMMA NUMBER
		{
#if defined(INET6)
	    char *a, *p;
	    struct sockaddr_in *data_dest_sin;

	    lport_error = 0;
	    if (epsv_all) {
		reply(501, "LPRT not allowed after EPSV ALL");
		lport_error = 1;
		goto lport_done4;
	    }
	    if ($1 != 4) {
		reply(521, "Supported address families are (4, 6)");
		lport_error = 1;
		goto lport_done4;
	    }
	    if (($3 != 4) || ($13 != 2)) {
		reply(501, "Bad length.");
		lport_error = 1;
		goto lport_done4;
	    }
	    data_dest_sin = (struct sockaddr_in *) &data_dest;
	    data_dest_sin->sin_family = AF_INET;
	    a = (char *)&data_dest_sin->sin_addr;
	    a[0] = $5; a[1] = $7; a[2] = $9; a[3] = $11;
	    p = (char *)&data_dest_sin->sin_port;
	    p[0] = $15; p[1] = $17;
lport_done4:;
#endif /* defined(INET6) */ 
	}
    ;

form_code: N
		{
	    $$ = FORM_N;
	}
    | T
		{
	    $$ = FORM_T;
	}
    | C
		{
	    $$ = FORM_C;
	}
    ;

type_code: A
		{
	    cmd_type = TYPE_A;
	    cmd_form = FORM_N;
	}
    | A SP form_code
		{
	    cmd_type = TYPE_A;
	    cmd_form = $3;
	}
    | E
		{
	    cmd_type = TYPE_E;
	    cmd_form = FORM_N;
	}
    | E SP form_code
		{
	    cmd_type = TYPE_E;
	    cmd_form = $3;
	}
    | I
		{
	    cmd_type = TYPE_I;
	}
    | L
		{
	    cmd_type = TYPE_L;
	    cmd_bytesz = NBBY;
	}
    | L SP byte_size
		{
	    cmd_type = TYPE_L;
	    cmd_bytesz = $3;
	}
    /* this is for a bug in the BBN ftp */
    | L byte_size
		{
	    cmd_type = TYPE_L;
	    cmd_bytesz = $2;
	}
    ;

prot_code: C
		{
	    $$ = PROT_C;
	}
    | P
		{
	    $$ = PROT_P;
	}
    | S
		{
	    $$ = PROT_S;
	}
    | E
		{
	    $$ = PROT_E;
	}
    ;


struct_code: F
		{
	    $$ = STRU_F;
	}
    | R
		{
	    $$ = STRU_R;
	}
    | P
		{
	    $$ = STRU_P;
	}
    ;

mode_code:  S
		{
	    $$ = MODE_S;
	}
    | B
		{
	    $$ = MODE_B;
	}
    | C
		{
	    $$ = MODE_C;
	}
    ;

pathname: pathstring
		{
	    /*
	     * Problem: this production is used for all pathname
	     * processing, but only gives a 550 error reply.
	     * This is a valid reply in some cases but not in others.
	     */
	    if (restricted_user && logged_in && $1 && strncmp($1, "/", 1) == 0) {
		/*
		 * This remaps the root so it is appearently at the user's home
		 * rather than the real root/chroot.
		 */
		size_t len = strlen($1) + 2;
		char **globlist;
		char *t = calloc(len, sizeof(char));
		if (t == NULL) {
		    errno = EAGAIN;
		    perror_reply(550, $1);
		    $$ = NULL;
		}
		else {
		    t[0] = '~';
		    t[1] = '\0';
		    if (strncmp($1, "/../", 4) == 0)
			strlcat(t, $1 + 3, len);
		    else if (strcmp($1, "/..") != 0)
			strlcat(t, $1, len);
		    globlist = ftpglob(t);
		    if (globerr) {
			reply(550, "%s", globerr);
			$$ = NULL;
			if (globlist) {
			    blkfree(globlist);
			    free((char *) globlist);
			}
		    }
		    else if (globlist && *globlist) {
			$$ = *globlist;
			blkfree(&globlist[1]);
			free((char *) globlist);
		    }
		    else {
			if (globlist) {
			    blkfree(globlist);
			    free((char *) globlist);
			}
			errno = ENOENT;
			perror_reply(550, $1);
			$$ = NULL;
		    }
		    free(t);
		}
		free($1);
	    }
	    else if (logged_in && $1 && strncmp($1, "~", 1) == 0) {
		char **globlist;

		globlist = ftpglob($1);
		if (globerr) {
		    reply(550, "%s", globerr);
		    $$ = NULL;
		    if (globlist) {
			blkfree(globlist);
			free((char *) globlist);
		    }
		}
		else if (globlist && *globlist) {
		    $$ = *globlist;
		    blkfree(&globlist[1]);
		    free((char *) globlist);
		}
		else {
		    if (globlist) {
			blkfree(globlist);
			free((char *) globlist);
		    }
		    errno = ENOENT;
		    perror_reply(550, $1);
		    $$ = NULL;
		}
		free($1);
	    }
	    else
		$$ = $1;
	}
    ;

pathstring: STRING
    ;

method: STRING
    ;

octal_number: NUMBER
		{
	    register int ret, dec, multby, digit;

	    /*
	     * Convert a number that was read as decimal number
	     * to what it would be if it had been read as octal.
	     */
	    dec = $1;
	    multby = 1;
	    ret = 0;
	    while (dec) {
		digit = dec % 10;
		if (digit > 7) {
		    ret = -1;
		    break;
		}
		ret += digit * multby;
		multby *= 8;
		dec /= 10;
	    }
	    $$ = ret;
	}
    ;

check_login: /* empty */
		{
	    if (logged_in)
		$$ = 1;
	    else {
		if (log_commands)
		    syslog(LOG_INFO, "cmd failure - not logged in");
		reply(530, "Please login with USER and PASS.");
		$$ = 0;
		yyerrorcalled = 1;
	    }
	}
    ;

bufsize: NUMBER
remote_mtu_size: NUMBER
    ;

%%

extern jmp_buf errcatch;

#define CMD 0			/* beginning of command */
#define ARGS    1		/* expect miscellaneous arguments */
#define STR1    2		/* expect SP followed by STRING */
#define STR2    3		/* expect STRING */
#define OSTR    4		/* optional SP then STRING */
#define ZSTR1   5		/* SP then optional STRING */
#define ZSTR2   6		/* optional STRING after SP */
#define SITECMD 7		/* SITE command */
#define NSTR    8		/* Number followed by a string */
#define STR3    9		/* expect STRING followed by optional SP then STRING */
#define OPTSARGS 20		/* a command token, followed by newargs */

struct tab cmdtab[] =
{
    {"USER", USER, STR1, 1, "<sp> username"},
    {"PASS", PASS, ZSTR1, 1, "<sp> password"},
    {"ACCT", ACCT, STR1, 0, "(specify account)"},
    {"SMNT", SMNT, ARGS, 0, "(structure mount)"},
    {"REIN", REIN, ARGS, 0, "(reinitialize server state)"},
    {"QUIT", QUIT, ARGS, 1, "(terminate service)",},
    {"PORT", PORT, ARGS, 1, "<sp> h1, h2, h3, h4, p1, p2"},
    {"PASV", PASV, ARGS, 1, "(set server in passive mode)"},
#if defined(INET6)
    {"EPRT", EPRT, STR1, 1, "<sp> |af|addr|port|"},
    {"EPSV", EPSV, OSTR, 1, "[<sp> af|ALL]"},
    {"LPRT", LPRT, ARGS, 1, "<sp> af, hal, h1, h2, ..., pal, p1, p2, ..."},
    {"LPSV", LPSV, ARGS, 1, "(set server in long passive mode)"},
#endif /* defined(INET6) */ 
    {"TYPE", TYPE, ARGS, 1, "<sp> [ A | E | I | L ]"},
    {"STRU", STRU, ARGS, 1, "(specify file structure)"},
    {"MODE", MODE, ARGS, 1, "(specify transfer mode)"},
    {"RETR", RETR, STR1, 1, "<sp> file-name"},
    {"STOR", STOR, STR1, 1, "<sp> file-name"},
    {"APPE", APPE, STR1, 1, "<sp> file-name"},
    {"MLFL", MLFL, OSTR, 0, "(mail file)"},
    {"MAIL", MAIL, OSTR, 0, "(mail to user)"},
    {"MSND", MSND, OSTR, 0, "(mail send to terminal)"},
    {"MSOM", MSOM, OSTR, 0, "(mail send to terminal or mailbox)"},
    {"MSAM", MSAM, OSTR, 0, "(mail send to terminal and mailbox)"},
    {"MRSQ", MRSQ, OSTR, 0, "(mail recipient scheme question)"},
    {"MRCP", MRCP, STR1, 0, "(mail recipient)"},
    {"ALLO", ALLO, ARGS, 1, "allocate storage (vacuously)"},
    {"REST", REST, STR1, 1, "(restart command)"},
    {"RNFR", RNFR, STR1, 1, "<sp> file-name"},
    {"RNTO", RNTO, STR1, 1, "<sp> file-name"},
    {"ABOR", ABOR, ARGS, 1, "(abort operation)"},
    {"DELE", DELE, STR1, 1, "<sp> file-name"},
    {"CWD", CWD, OSTR, 1, "[ <sp> directory-name ]"},
    {"XCWD", CWD, OSTR, 2, "[ <sp> directory-name ]"},
    {"LIST", LIST, OSTR, 1, "[ <sp> path-name ]"},
    {"MLSD", MLSD, OSTR, 1, "[ <sp> path-name ]"},
    {"MLST", MLST, OSTR, 1, "[ <sp> path-name ]"},
    {"NLST", NLST, OSTR, 1, "[ <sp> path-name ]"},
#if defined(DISABLE_SITE)
    {"SITE", SITE, SITECMD, 0, "site-cmd [ <sp> arguments ]"},
#else /* !(defined(DISABLE_SITE)) */ 
    {"SITE", SITE, SITECMD, 1, "site-cmd [ <sp> arguments ]"},
#endif /* !(defined(DISABLE_SITE)) */ 
    {"SYST", SYST, ARGS, 1, "(get type of operating system)"},
    {"STAT", STAT, OSTR, 1, "[ <sp> path-name ]"},
    {"HELP", HELP, OSTR, 1, "[ <sp> <string> ]"},
    {"NOOP", NOOP, ARGS, 1, ""},
    {"MKD", MKD, STR1, 1, "<sp> path-name"},
    {"XMKD", MKD, STR1, 2, "<sp> path-name"},
    {"RMD", RMD, STR1, 1, "<sp> path-name"},
    {"XRMD", RMD, STR1, 2, "<sp> path-name"},
    {"PWD", PWD, ARGS, 1, "(return current directory)"},
    {"XPWD", PWD, ARGS, 2, "(return current directory)"},
    {"CDUP", CDUP, ARGS, 1, "(change to parent directory)"},
    {"XCUP", CDUP, ARGS, 2, "(change to parent directory)"},
    {"STOU", STOU, OSTR, 1, "[ <sp> file-name ]"},
    {"SIZE", SIZE, OSTR, 1, "<sp> path-name"},
    {"MDTM", MDTM, OSTR, 1, "<sp> path-name"},
#if defined(USE_SECURITY)
    {"PROT", PROT, ARGS, 1, "<sp> protection-level"},
    {"PBSZ", PBSZ, STR1, 1, "<sp> protection-buffer-size"},
    {"AUTH", AUTH, STR1, 1, "<sp> authentication-mechanism"},
    {"CCC", CCC, ARGS, 1, "(clear command channel)"},
    {"ADAT", ADAT, STR1, 1, "<sp> authentication-data"},
#endif /* defined(USE_SECURITY) */
    { "FEAT", FEAT, ARGS, 1, "(return list of FTP extensions supported)"},
    { "OPTS", OPTS, OPTSARGS, 1, "(set operation-specific options)"},
    { "MFF", MFF, ARGS, 1, "(set file facts)"},
    { "MFCT", MFCT, ARGS, 1, "(set creation time)"},
    { "MFMT", MFMT, ARGS, 1, "(set modification time)"},
    { "CSID", CSID, STR1, 1, "(<sp> client/server info)"},
    { "CLNT", CLNT, STR1, 1, "(<sp> client info)"},
#if defined(AUTOBUF)
    {"SBUF", SBUF, ARGS, 1, "[ <sp> <socket buffer size in bytes> ]"},
#endif /* defined(AUTOBUF) */
    {NULL, 0, 0, 0, 0}
};

struct tab optstab[] =
{
    {"MLST", MLST, OSTR, 1, "[ <sp> <fact list> ]"},
    {NULL, 0, 0, 0, 0}
};

char * feattab[] =
{
    "CSID",
    "CLNT",
    "EPRT",
    "EPSV",
    "MDTM",
    "MLST Type*;Size*;Modify*;Perm*;Charset*;UNIX.mode*;UNIX.slink*;Unique*;",
    "PASV",
    "REST STREAM",
#if defined(AUTOBUF)
    "SBUF",
    "SITE BUFSIZE",
    "SITE BUFSIZEMEASURE",
#endif /* defined(AUTOBUF) */
#if !defined(DISABLE_SITE_CHECKSUM)
    "SITE CHECKSUM",
#endif /* !defined(DISABLE_SITE_CHECKSUM) */
#if !defined(DISABLE_SITE_CHECKMETHOD)
    "SITE CHECKMETHOD",
#endif /* !(defined(DISABLE_SITE_CHECKMETHOD)) */
    "SIZE",
    "TVFS",
    NULL
};

struct tab sitetab[] =
{
#if defined(DISABLE_SITE_UMASK)
    {"UMASK", UMASK, ARGS, 0, "[ <sp> umask ]"},
#else /* !(defined(DISABLE_SITE_UMASK)) */ 
    {"UMASK", UMASK, ARGS, 1, "[ <sp> umask ]"},
#endif /* !(defined(DISABLE_SITE_UMASK)) */ 
#if defined(DISABLE_SITE_IDLE)
    {"IDLE", IDLE, ARGS, 0, "[ <sp> maximum-idle-time ]"},
#else /* !(defined(DISABLE_SITE_IDLE)) */ 
    {"IDLE", IDLE, ARGS, 1, "[ <sp> maximum-idle-time ]"},
#endif /* !(defined(DISABLE_SITE_IDLE)) */ 
#if defined(DISABLE_SITE_CHMOD)
    {"CHMOD", CHMOD, NSTR, 0, "<sp> mode <sp> file-name"},
#else /* !(defined(DISABLE_SITE_CHMOD)) */ 
    {"CHMOD", CHMOD, NSTR, 1, "<sp> mode <sp> file-name"},
#endif /* !(defined(DISABLE_SITE_CHMOD)) */ 
    {"HELP", HELP, OSTR, 1, "[ <sp> <string> ]"},
#if !defined(NO_PRIVATE)
    {"GROUP", GROUP, STR1, 1, "<sp> access-group"},
    {"GPASS", GPASS, OSTR, 1, "<sp> access-password"},
#else /* !(!defined(NO_PRIVATE)) */ 
    {"GROUP", GROUP, STR1, 0, "<sp> access-group"},
    {"GPASS", GPASS, OSTR, 0, "<sp> access-password"},
#endif /* !(!defined(NO_PRIVATE)) */ 
#if defined(SITE_NEWER)
    {"NEWER", NEWER, STR3, 1, "<sp> YYYYMMDDHHMMSS [ <sp> path-name ]"},
    {"MINFO", MINFO, STR3, 1, "<sp> YYYYMMDDHHMMSS [ <sp> path-name ]"},
#else /* !(defined(SITE_NEWER)) */ 
    {"NEWER", NEWER, STR3, 0, "<sp> YYYYMMDDHHMMSS [ <sp> path-name ]"},
    {"MINFO", MINFO, STR3, 0, "<sp> YYYYMMDDHHMMSS [ <sp> path-name ]"},
#endif /* !(defined(SITE_NEWER)) */ 
#if defined(ENABLE_SITE_EXEC)
    {"INDEX", INDEX, STR1, 1, "<sp> pattern"},
    {"EXEC", EXEC, STR1, 1, "<sp> command [ <sp> arguments ]"},
#else /* !(defined(ENABLE_SITE_EXEC)) */ 
    {"INDEX", INDEX, STR1, 0, "<sp> pattern"},
    {"EXEC",  EXEC,  STR1, 0, "<sp> command [ <sp> arguments ]"},
#endif /* !(defined(ENABLE_SITE_EXEC)) */ 
#if defined(DISABLE_SITE_ALIAS)
    {"ALIAS", ALIAS, OSTR, 0, "[ <sp> alias ] "},
#else /* !(defined(DISABLE_SITE_ALIAS)) */ 
    {"ALIAS", ALIAS, OSTR, 1, "[ <sp> alias ] "},
#endif /* !(defined(DISABLE_SITE_ALIAS)) */ 
#if defined(DISABLE_SITE_CDPATH)
    {"CDPATH", CDPATH, OSTR, 0, "[ <sp> ] "},
#else /* !(defined(DISABLE_SITE_CDPATH)) */ 
    {"CDPATH", CDPATH, OSTR, 1, "[ <sp> ] "},
#endif /* !(defined(DISABLE_SITE_CDPATH)) */ 
#if defined(DISABLE_SITE_GROUPS)
    {"GROUPS", GROUPS, OSTR, 0, "[ <sp> ] "},
#else /* !(defined(DISABLE_SITE_GROUPS)) */ 
    {"GROUPS", GROUPS, OSTR, 1, "[ <sp> ] "},
#endif /* !(defined(DISABLE_SITE_GROUPS)) */ 
#if defined(DISABLE_SITE_CHECKMETHOD)
    {"CHECKMETHOD", CHECKMETHOD, OSTR, 0, "[ <sp> crc|md5 ]"},
#else /* !(defined(DISABLE_SITE_CHECKMETHOD)) */ 
    {"CHECKMETHOD", CHECKMETHOD, OSTR, 1, "[ <sp> crc|md5 ]"},
#endif /* !(defined(DISABLE_SITE_CHECKMETHOD)) */ 
#if defined(DISABLE_SITE_CHECKSUM)
    {"CHECKSUM", CHECKSUM, OSTR, 0, "[ <sp> file-name ]"},
#else /* !(defined(DISABLE_SITE_CHECKSUM)) */ 
    {"CHECKSUM", CHECKSUM, OSTR, 1, "[ <sp> file-name ]"},
#endif /* !(defined(DISABLE_SITE_CHECKSUM)) */ 
#if defined(AUTOBUF)
    {"BUFSIZE", BUFSIZE, ARGS, 1, "[ <sp> <socket buffer size in bytes> ]"},
    {"BUFSIZEMEASURE", BUFSIZEMEASURE, ARGS, 1, "[ <sp> <remote mtu in bytes> ]"},
#endif /* defined(AUTOBUF) */
    {NULL, 0, 0, 0, 0}
};

struct tab *lookup(register struct tab *p, char *cmd)
{
    for (; p->name != NULL; p++)
	if (strcmp(cmd, p->name) == 0)
	    return (p);
    return (0);
}

#include <arpa/telnet.h>

/************************************************************************
**
** getline - a hacked up version of fgets to ignore TELNET escape codes.
**
************************************************************************/
char *wu_getline(char *s, int n, register FILE *iop)
{
    register int c;
    register char *cs;
    char *passtxt = "PASS password\r\n";

    cs = s;
/* tmpline may contain saved command from urgent mode interruption */
    for (c = 0; tmpline[c] != '\0' && --n > 0; ++c) {
	*cs++ = tmpline[c];
	if (tmpline[c] == '\n') {
	    *cs++ = '\0';
	    if (debug) {
		if (strncasecmp(passtxt, s, 5) == 0)
		    syslog(LOG_DEBUG, "command: %s", passtxt);
		else
		    syslog(LOG_DEBUG, "command: %s", s);
	    }
	    tmpline[0] = '\0';
	    return (s);
	}
	if (c == 0)
	    tmpline[0] = '\0';
    }
  retry:
    while ((c = GETC(iop)) != EOF) {
#if defined(TRANSFER_COUNT)
	byte_count_total++;
	byte_count_in++;
#endif /* defined(TRANSFER_COUNT) */ 
	c &= 0377;
	if (c == IAC) {
	    if ((c = GETC(iop)) != EOF) {
#if defined(TRANSFER_COUNT)
		byte_count_total++;
		byte_count_in++;
#endif /* defined(TRANSFER_COUNT) */ 
		c &= 0377;
		switch (c) {
		case WILL:
		case WONT:
		    c = GETC(iop);
#if defined(TRANSFER_COUNT)
		    byte_count_total++;
		    byte_count_in++;
#endif /* defined(TRANSFER_COUNT) */ 
		    PRINTF("%c%c%c", IAC, DONT, 0377 & c);
		    (void) FFLUSH(stdout);
		    continue;
		case DO:
		case DONT:
		    c = GETC(iop);
#if defined(TRANSFER_COUNT)
		    byte_count_total++;
		    byte_count_in++;
#endif /* defined(TRANSFER_COUNT) */ 
		    PRINTF("%c%c%c", IAC, WONT, 0377 & c);
		    (void) FFLUSH(stdout);
		    continue;
		case IAC:
		    break;
		default:
		    continue;	/* ignore command */
		}
	    }
	}
	*cs++ = c;
	if (--n <= 0 || c == '\n')
	    break;
    }

    if (c == EOF && cs == s) {
	if (ferror(iop) && (errno == EINTR))
	    goto retry;
	return (NULL);
    }

    *cs++ = '\0';
#if defined(USE_GSS)
    if (sec_check_mechanism(SEC_MECHANISM_GSS) && 
	(gss_info.authstate & GSS_ADAT_DONE) &&
	gss_info.context != GSS_C_NO_CONTEXT) {
	s = sec_decode_command(s);
    } else if (sec_check_mechanism(SEC_MECHANISM_GSS) &&
	(!strncmp(s, "ENC", 3) || !strncmp(s, "MIC", 3) ||
	!strncmp(s, "CONF", 4)) &&
	!(gss_info.authstate & GSS_ADAT_DONE)) {
	if (debug)
	    syslog(LOG_DEBUG, "command: %s", s);
	reply(503, "Must perform authentication before sending protected commands");
    	*s = '\0';
	return(s);
    }
#endif /* USE_GSS */

    if (debug) {
	if (strncasecmp(passtxt, s, 5) == 0)
	    syslog(LOG_DEBUG, "command: %s", passtxt);
	else
	    syslog(LOG_DEBUG, "command: %s", s);
    }
    return (s);
}

static void toolong(int a) /* signal that caused this function to be called */
{
    time_t now;

    reply(421,
	  "Timeout (%d seconds): closing control connection.", timeout_idle);
    (void) time(&now);
    if (logging) {
	syslog(LOG_INFO,
	       "User %s timed out after %d seconds at %.24s",
	       (pw ? pw->pw_name : "unknown"), timeout_idle, ctime(&now));
    }
    dologout(1);
}

int yylex(void)
{
    static int cpos, state;
    register char *cp, *cp2;
    register struct tab *p;
    int n;
    time_t now;
    char c = '\0';
    extern time_t limit_time;
    extern time_t login_time;

    for (;;) {
	switch (state) {

	case CMD:
	    yyerrorcalled = 0;

	    setproctitle("%s: IDLE", proctitle);

	    if (is_shutdown(!logged_in, 0) != 0) {
		reply(221, "Server shutting down.  Goodbye.");
		dologout(0);
	    }

	    time(&now);
	    if ((limit_time > 0) && (((now - login_time) / 60) >= limit_time)) {
		reply(221, "Time limit reached.  Goodbye.");
		dologout(0);
	    }

#if defined(IGNORE_NOOP)
	    if (!alarm_running) {
		(void) signal(SIGALRM, toolong);
		(void) alarm((unsigned) timeout_idle);
		alarm_running = 1;
	    }
#else /* !(defined(IGNORE_NOOP)) */ 
	    (void) signal(SIGALRM, toolong);
	    (void) alarm((unsigned) timeout_idle);
#endif /* !(defined(IGNORE_NOOP)) */ 
	    if (wu_getline(cbuf, sizeof(cbuf) - 1, stdin) == NULL) {
		(void) alarm(0);
		reply(221, "You could at least say goodbye.");
		dologout(0);
	    }
#if !defined(IGNORE_NOOP)
	    (void) alarm(0);
#endif /* !defined(IGNORE_NOOP) */ 
	    if ((cp = strchr(cbuf, '\r'))) {
		*cp++ = '\n';
		*cp = '\0';
	    }
	    if ((cp = strpbrk(cbuf, " \n")))
		cpos = cp - cbuf;
	    if (cpos == 0)
		cpos = 4;
	    c = cbuf[cpos];
	    cbuf[cpos] = '\0';
	    upper(cbuf);
#if defined(IGNORE_NOOP)
	    if (strncasecmp(cbuf, "NOOP", 4) != 0) {
		(void) alarm(0);
		alarm_running = 0;
	    }
#endif /* defined(IGNORE_NOOP) */ 
	    p = lookup(cmdtab, cbuf);
	    cbuf[cpos] = c;
	    if (strncasecmp(cbuf, "PASS", 4) != 0 &&
		strncasecmp(cbuf, "SITE GPASS", 10) != 0) {
		if ((cp = strchr(cbuf, '\n')))
		    *cp = '\0';
		setproctitle("%s: %s", proctitle, cbuf);
		if (cp)
		    *cp = '\n';
	    }
	    if (p != 0) {
		if (p->implemented == 0) {
		    nack(p->name);
		    longjmp(errcatch, 0);
		    /* NOTREACHED */
		}
		state = p->state;
		yylval.String = p->name;
		return (p->token);
	    }
	    break;

	case SITECMD:
	    if (cbuf[cpos] == ' ') {
		cpos++;
		return (SP);
	    }
	    cp = &cbuf[cpos];
	    if ((cp2 = strpbrk(cp, " \n")))
		cpos = cp2 - cbuf;
	    c = cbuf[cpos];
	    cbuf[cpos] = '\0';
	    upper(cp);
	    p = lookup(sitetab, cp);
	    cbuf[cpos] = c;
	    if (p != 0) {
#if !defined(DISABLE_SITE)		/* what GOOD is SITE *, anyways?!  _H */
		if (p->implemented == 0) {
#else /* !(!defined(DISABLE_SITE) - what GOOD is SITE *, anyways?!  _H */
		if (1) {
		    syslog(LOG_WARNING, "refused SITE %s %s from %s of %s",
			   p->name, &cbuf[cpos],
			   anonymous ? guestpw : authuser, remoteident);
#endif /* !(!defined(DISABLE_SITE) -  what GOOD is SITE *, anyways?!  _H */
		    state = CMD;
		    nack(p->name);
		    longjmp(errcatch, 0);
		    /* NOTREACHED */
		}
		state = p->state;
		yylval.String = p->name;
		return (p->token);
	    }
	    state = CMD;
	    break;

	case OSTR:
	    if (cbuf[cpos] == '\n') {
		state = CMD;
		return (CRLF);
	    }
	    /* FALLTHROUGH */

	case STR1:
	case ZSTR1:
	  dostr1:
	    if (cbuf[cpos] == ' ') {
		cpos++;
		if (state == OSTR)
		    state = STR2;
		else
		    ++state;
		return (SP);
	    }
	    break;

	case ZSTR2:
	    if (cbuf[cpos] == '\n') {
		state = CMD;
		return (CRLF);
	    }
	    /* FALLTHROUGH */

	case STR2:
	    cp = &cbuf[cpos];
	    n = strlen(cp);
	    cpos += n - 1;
	    /*
	     * Make sure the string is nonempty and \n terminated.
	     */
	    if (n > 1 && cbuf[cpos] == '\n') {
		cbuf[cpos] = '\0';
		yylval.String = copy(cp);
		cbuf[cpos] = '\n';
		state = ARGS;
		return (STRING);
	    }
	    break;

	case NSTR:
	    if (cbuf[cpos] == ' ') {
		cpos++;
		return (SP);
	    }
	    if (isdigit(cbuf[cpos])) {
		cp = &cbuf[cpos];
		while (isdigit(cbuf[++cpos]));
		c = cbuf[cpos];
		cbuf[cpos] = '\0';
		yylval.Number = atoi(cp);
		cbuf[cpos] = c;
		state = STR1;
		return (NUMBER);
	    }
	    state = STR1;
	    goto dostr1;

	case STR3:
	    if (cbuf[cpos] == ' ') {
		cpos++;
		return (SP);
	    }

	    cp = &cbuf[cpos];
	    cp2 = strpbrk(cp, " \n");
	    if (cp2 != NULL) {
		c = *cp2;
		*cp2 = '\0';
	    }
	    n = strlen(cp);
	    cpos += n;
	    /*
	     * Make sure the string is nonempty and SP terminated.
	     */
	    if ((cp2 - cp) > 1) {
		yylval.String = copy(cp);
		cbuf[cpos] = c;
		state = OSTR;
		return (STRING);
	    }
	    break;

	case ARGS:
	    if (isdigit(cbuf[cpos])) {
		cp = &cbuf[cpos];
		while (isdigit(cbuf[++cpos]));
		c = cbuf[cpos];
		cbuf[cpos] = '\0';
		yylval.Number = atoi(cp);
		cbuf[cpos] = c;
		return (NUMBER);
	    }
	    switch (cbuf[cpos++]) {

	    case '\n':
		state = CMD;
		return (CRLF);

	    case ' ':
		return (SP);

	    case ',':
		return (COMMA);

	    case 'A':
	    case 'a':
		return (A);

	    case 'B':
	    case 'b':
		return (B);

	    case 'C':
	    case 'c':
		return (C);

	    case 'E':
	    case 'e':
		return (E);

	    case 'F':
	    case 'f':
		return (F);

	    case 'I':
	    case 'i':
		return (I);

	    case 'L':
	    case 'l':
		return (L);

	    case 'N':
	    case 'n':
		return (N);

	    case 'P':
	    case 'p':
		return (P);

	    case 'R':
	    case 'r':
		return (R);

	    case 'S':
	    case 's':
		return (S);

	    case 'T':
	    case 't':
		return (T);

	    }
	    break;

	case OPTSARGS:
	    if (cbuf[cpos] == ' ') {
		cpos++;
		return (SP);
	    }
	    cp = &cbuf[cpos];
	    if ((cp2 = strpbrk(cp, " \n")))
		cpos = cp2 - cbuf;
	    c = cbuf[cpos];
	    cbuf[cpos] = '\0';
	    upper(cp);
	    p = lookup(optstab, cp);
	    cbuf[cpos] = c;
	    if (p != 0) {
		if (p->implemented == 0) {
		    state = CMD;
		    nack(p->name);
		    longjmp(errcatch, 0);
		    /* NOTREACHED */
		}
		state = p->state;
		yylval.String = p->name;
		return (p->token);
	    }
	    state = CMD;
	    break;

	default:
	    fatal("Unknown state in scanner.");
	}
	if (yyerrorcalled == 0) {
	    if ((cp = strchr(cbuf, '\n')) != NULL)
		*cp = '\0';
	    if (logged_in)
		reply(500, "'%s': command not understood.", cbuf);
	    else
		reply(530, "Please login with USER and PASS.");
	}
	state = CMD;
	longjmp(errcatch, 0);
    }
}

void upper(char *s)
{
    while (*s != '\0') {
	if (islower(*s))
	    *s = toupper(*s);
	s++;
    }
}

char *copy(char *s)
{
    char *p;

    p = strdup(s);
    if (p == NULL)
	fatal("Ran out of memory.");
    return (p);
}

/************************************************************************
**
**
**
************************************************************************/
void help(struct tab *ctab, char *s)
{
    struct aclmember *entry = NULL;
    struct tab *c;
    size_t width = 0, NCMDS = 0;
    char *type;

    for (c = ctab; c->name != NULL; c++) {
	if (c->implemented == 1) {
	    size_t len = strlen(c->name);
	    if (len > width)
		width = len;
	    NCMDS++;
	}
    }
    width = (width + 8) & ~7;

    if (ctab == sitetab) {
	/* Only give help on SITE commands if the SITE command is implemented */
	if ((c = lookup(cmdtab, "SITE")) == (struct tab *) NULL) {
	    reply(502, "Unknown command %s.", "SITE");
	    return;
	}
	if (!c->implemented) {
	    reply(214, "%-*s\t%s; unimplemented.", width, c->name, c->help);
	    return;
	}
	type = "SITE ";
    }
    else
	type = "";

    if (s == 0) {
	register size_t i, j, k, w;
	size_t columns, lines;

	lreply(214, "The following %scommands are implemented.", type);
	columns = 76 / width;
	if (columns == 0)
	    columns = 1;
	lines = (NCMDS + columns - 1) / columns;
	for (i = 0; i < lines; i++) {
	    char line[1024], *ptr = line;
	    ptr += strlcpy(line, "   ", sizeof(line));
	    /* Find first entry on line */
	    for (k = 0, c = ctab;; c++)
		if (c->implemented == 1 && k++ == i)
		    break;
	    for (j = 0; j < columns; j++) {
		(void) snprintf(ptr, line + sizeof(line) - ptr, "%s", c->name);
		w = strlen(c->name);
		ptr += w;
		/* Find next entry on line */
		for (k = 0, c++; c->name != NULL; c++)
		    if (c->implemented == 1 && ++k == lines)
			break;
		if (c->name == NULL)
		    break;
		while (w < width) {
		    *(ptr++) = ' ';
		    w++;
		}
	    }
	    *ptr = '\0';
	    lreply(0, "%s", line);
	}
	(void) FFLUSH(stdout);
#if defined(VIRTUAL)
	if (virtual_mode && !virtual_ftpaccess && virtual_email[0] != '\0')
	    reply(214, "Direct comments to %s.", virtual_email);
	else
#endif /* defined(VIRTUAL) */ 
	if ((getaclentry("email", &entry)) && ARG0)
	    reply(214, "Direct comments to %s.", ARG0);
	else
	    reply(214, "Direct comments to ftp-bugs@%s.", hostname);
	return;
    }
    upper(s);
    c = lookup(ctab, s);
    if (c == (struct tab *) NULL) {
	reply(502, "Unknown command %s.", s);
	return;
    }
    if (c->implemented)
	reply(214, "Syntax: %s%s %s", type, c->name, c->help);
    else
	reply(214, "%s%-*s\t%s; unimplemented.", type, width,
	      c->name, c->help);
}

/*************************************************************************
**
** From RFC 2389
**
*************************************************************************/
void feat(char *tab[])
{
    int i;

    if(tab[0] == NULL)
    {
	reply(211, "No features supported");
	return;
    }
    lreply(211, "Extensions supported:");
    for(i = 0; tab[i] != NULL; i++)
    {
	lreply(0, " %s", feattab[i]);
    }
    reply(211, "END");
}

/*************************************************************************
**
** Obtain the size of a file
** 
*************************************************************************/
void sizecmd(char *filename)
{
    switch (type) {
    case TYPE_L:
    case TYPE_I:{
	    struct stat stbuf;
	    if (stat(filename, &stbuf) < 0 ||
		(stbuf.st_mode & S_IFMT) != S_IFREG)
		reply(550, "%s: not a plain file.", filename);
	    else {
		if (sizeof(stbuf.st_size) <= sizeof(unsigned int))
		    reply(213, "%" L_FORMAT, stbuf.st_size);
		else if (sizeof(stbuf.st_size) <= sizeof(unsigned long int))
		    reply(213, "%l", L_FORMAT, stbuf.st_size);
		else if (sizeof(stbuf.st_size) <= sizeof(unsigned long long int))
		    reply(213, "%ll", L_FORMAT, stbuf.st_size);
		else
		    reply(504, "Size of file %s out of range.", filename);
		}
	    break;
	}
    default:
	reply(504, "SIZE not implemented for Type %c.", "?AEIL"[type]);
    }
}

/*************************************************************************
**
** site_exec()
**
*************************************************************************/
void site_exec(char *cmd)
{
#if !defined(ENABLE_SITE_EXEC)
    syslog(LOG_CRIT, "REFUSED SITE_EXEC (slipped through!!): %s", cmd);
    reply(502, "%s command not implemented.", "SITE EXEC");
#else /* !(!defined(ENABLE_SITE_EXEC)) */ 
    char buf[MAXPATHLEN];
    char *sp = (char *) strchr(cmd, ' '), *slash, *t;
    FILE *cmdf;


    /* sanitize the command-string */

    if (sp == 0) {
	while ((slash = strchr(cmd, '/')) != 0)
	    cmd = slash + 1;
    }
    else {
	while (sp && (slash = (char *) strchr(cmd, '/'))
	       && (slash < sp))
	    cmd = slash + 1;
    }

    for (t = cmd; *t && !isspace(*t); t++) {
	if (isupper(*t)) {
	    *t = tolower(*t);
	}
    }

    /* build the command */
    if (strlen(_PATH_EXECPATH) + strlen(cmd) + 2 > sizeof(buf))
	return;
    snprintf(buf, sizeof(buf), "%s/%s", _PATH_EXECPATH, cmd);

    cmdf = ftpd_popen(buf, "r", 0);
    if (!cmdf) {
	perror_reply(550, cmd);
	if (log_commands)
	    syslog(LOG_INFO, "SITE EXEC (FAIL: %m): %s", cmd);
    }
    else {
	int lines = 0;
	int maxlines = 0;
	struct aclmember *entry = NULL;
	char class[1024];
	int maxfound = 0;
	int defmaxlines = 20;
	int which;

	(void) acl_getclass(class, sizeof(class));
	while ((getaclentry("site-exec-max-lines", &entry))) {
	    if (!ARG0)
		continue;
	    if (ARG1)
		for (which = 1; (which < MAXARGS) && ARG[which]; which++) {
		    if (!strcasecmp(ARG[which], class)) {
			maxlines = atoi(ARG0);
			maxfound = 1;
		    }
		    if (!strcmp(ARG[which], "*"))
			defmaxlines = atoi(ARG0);
		}
	    else
		defmaxlines = atoi(ARG0);
	}
	if (!maxfound)
	    maxlines = defmaxlines;
	lreply(200, "%s", cmd);
	while (fgets(buf, sizeof buf, cmdf)) {
	    size_t len = strlen(buf);

	    if (len > 0 && buf[len - 1] == '\n')
		buf[--len] = '\0';
	    lreply(200, "%s", buf);
	    if (maxlines <= 0)
		++lines;
	    else if (++lines >= maxlines) {
		lreply(200, "*** Truncated ***");
		break;
	    }
	}
	reply(200, " (end of '%s')", cmd);
	if (log_commands)
	    syslog(LOG_INFO, "SITE EXEC (lines: %d): %s", lines, cmd);
	ftpd_pclose(cmdf);
    }
#endif /* !(!defined(ENABLE_SITE_EXEC)) */ 
}

/*********************************************************************
 * sanitise arguments to ls, to avoid -w DoS with GNU ls 
**********************************************************************/
char *sanitise_ls_args(char *inp)
{
    char *ls_args, *inp_p, *ls_args_p;

    if (inp == NULL)
	return NULL;

    ls_args = malloc(strlen(inp) + 1);
    inp_p = inp;
    ls_args_p = ls_args;

    while(*inp_p != '\0') {
	if (strncasecmp(inp_p,"-w",2) == 0) {
	    /* skip -w and its argument */
	    inp_p += 2;
	    for (;*inp_p != '\0' && isspace(*inp_p);inp_p++);
	    for (;*inp_p != '\0' && !isspace(*inp_p);inp_p++);
	} else if (strncasecmp(inp_p,"--width",7) == 0) {
	    /* same with the long option */
	    inp_p += 7;
	    for (;*inp_p != '\0' && isspace(*inp_p);inp_p++);
	    for (;*inp_p != '\0' && !isspace(*inp_p);inp_p++);
	} else {
	    *ls_args_p = *inp_p;
	    ++ls_args_p;
	    ++inp_p;
	}
    }
}

void alias(char *s)
{
    struct aclmember *entry = NULL;

    if (s != (char *) NULL) {
	while (getaclentry("alias", &entry)) {
	    if (!ARG0 || !ARG1)
		continue;
	    if (!strcmp(ARG0, s)) {
		reply(214, "%s is an alias for %s.", ARG0, ARG1);
		return;
	    }
	}
	reply(502, "Unknown alias %s.", s);
	return;
    }

    lreply(214, "The following aliases are available.");

    while (getaclentry("alias", &entry)) {
	if (!ARG0 || !ARG1)
	    continue;
	lreply(0, "   %-8s %s", ARG0, ARG1);
    }
    (void) FFLUSH(stdout);

    reply(214, "");
}

void cdpath(void)
{
    struct aclmember *entry = NULL;

    lreply(214, "The cdpath is:");
    while (getaclentry("cdpath", &entry)) {
	if (ARG0)
	    lreply(0, "  %s", ARG0);
    }
    (void) FFLUSH(stdout);
    reply(214, "");
}

void print_groups(void)
{
    gid_t groups[NGROUPS_MAX];
    int ngroups = 0;

    if ((ngroups = getgroups(NGROUPS_MAX, groups)) < 0) {
	return;
    }

    lreply(214, "Group membership is:");
    ngroups--;

    for (; ngroups >= 0; ngroups--)
	lreply(214, "  %d", groups[ngroups]);

    (void) FFLUSH(stdout);
    reply(214, "");
}

/*************************************************************************
**
** Modified by Gaurav Navlakha for Auto Tuning, NLANR, adapted by wfms.
**
*************************************************************************/
#if defined(AUTOBUF)
void set_bufsize(int size)
{
    /* Use the new Window Size sent by client for data connection */
    TCPwindowsize = size;

    reply(214, "TCP window size set to %d kilobytes.",  TCPwindowsize);

    if (debug)
	syslog(LOG_DEBUG, "set_bufsize: TCPwindowsize = [%d]\n", TCPwindowsize);
}

void print_bufsize(void)
{
    if (TCPwindowsize > 0)
	reply(214, "TCP window size is %d kilobytes.", TCPwindowsize);
    else
	reply(214, "TCP window size is the system default.");
}

void udp_timeout(int signo)
{
    all_lost = 1;

    /* cancel the interval timer */
    val.it_interval.tv_sec = 0;
    val.it_interval.tv_usec = 0;
    val.it_value.tv_sec = 0;
    val.it_value.tv_usec = 0;
}

int measure_bufsize(int size)
{
    static int i = 0;
    int conn = -1;
    buf_udp_t sendreply[UDP_PKT_SIZE/(sizeof(buf_udp_t))];
    struct sockaddr_in addr;
    int yes = 1;
    int n=0;

    struct sockaddr_in cli_addr;
    socklen_t addrlen;
    struct pollfd fds[1];
    int seqno;

    /* Signals for setting up interval (2 sec) timer */
    struct sigaction action;
    struct sigaction oldaction;

    all_lost = 0;

    val.it_interval.tv_sec = 0;
    val.it_interval.tv_usec = 0;
    val.it_value.tv_sec = INTERVAL_SEC;
    val.it_value.tv_usec = INTERVAL_USEC;

    /* set up interval timer */
    sigemptyset(&action.sa_mask);
    action.sa_handler = udp_timeout;
    action.sa_flags = SA_RESTART;
    if(sigaction(SIGALRM, &action, &oldaction) == -1){
	return (-1);
    }

    if(setitimer(ITIMER_REAL, &val, 0) == -1){
	return (-1);
    }

    ++i;

    reply(211, "Got SITE BUFSIZEMEASURE command [%d]", size);

    if (debug)
	syslog(LOG_DEBUG, "Got SITE BUFSIZEMEASURE command [%d]", size);

    /* Create and bind the socket only once initially */
    if (udp_conn_setup==0)
    {
	if ((udp_conn = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
	{
	    return (-1);
	}
	if (setsockopt(udp_conn, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1)
	{
	    if (debug)
		syslog(LOG_DEBUG, "Error in call to setsockopt(SO_REUSEADDR)\n");
	    return (-1);
	}

	addr.sin_family = AF_INET;	     /* host byte order */
	addr.sin_port = htons(9001);	     /* short, network byte order */
	addr.sin_addr.s_addr = INADDR_ANY;   /* automatically fill with my IP */
	bzero(&(addr.sin_zero), sizeof(addr.sin_zero));         /* zero the rest of the struct */

	if (bind(udp_conn, (struct sockaddr *)&addr, sizeof(struct sockaddr)) == -1)
	{
	    return;
	}
	udp_conn_setup = 1;
    }

    fds[0].fd = udp_conn;
    fds[0].events = POLLIN;

    i=0;
    while (!all_lost && i<UDP_NUMBER_OF_PACKAGES)
    {
	if (poll(fds, 1, 0) == -1)
	{
	    if (errno == EINTR) /* interrupted by alarm */
	    {
		continue;
	    }
	    else
	    {
		perror("poll");
		continue;
	    }
	}
	if (!(fds[0].revents & POLLIN))
	    continue;

	++i;

	if ((n=recvfrom(udp_conn, (void *)sendreply, size, 0,
	    &cli_addr, &addrlen))<0)
	{
	    if (debug)
		syslog(LOG_DEBUG, "recv error [%d]\n", errno);
	    return (-1);
	}
	seqno = sendreply[0].seqno; /* this might be reverse byte order */
	if (debug) {
	    syslog(LOG_DEBUG, "Got SeqNo [%d] [%d]\n", seqno, ntohs(seqno));
	    syslog(LOG_DEBUG, "Bytes RECVD: [%d]\n", n);
	}
	if ((n=sendto(udp_conn, (const void *)sendreply, sizeof(buf_udp_t), 0,
	    (struct sockaddr *)&cli_addr, sizeof(struct sockaddr))) <0)
	{
	    if (debug)
		syslog(LOG_DEBUG, "send() error ");
	    return (-1);
	}
	if (debug)
	    syslog(LOG_DEBUG, "Reply [%d] - [%d] bytes sent\n", i, n);
	if (i==UDP_NUMBER_OF_PACKAGES)
	    break;
    }
    alarm(0);
    sigaction(SIGALRM, &oldaction, 0);
}
#endif /* defined(AUTOBUF) */

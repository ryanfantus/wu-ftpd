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
 
  $Id: getpwnam.c,v 1.9 2011/10/20 22:58:10 wmaton Exp $
 
****************************************************************************/
/*
 * Replacement for getpwnam - we need it to handle files other than
 * /etc/passwd so we can permit different passwd files for each different
 * host
 * 19980930	Initial version
 * 20000211	Various fixes
 */

#include "config.h"
#include <pwd.h>
#include <sys/types.h>
#include <stdio.h>
#include <ctype.h>
#if defined(SHADOW_PASSWORD)
#  if defined(HAVE_SHADOW_H)
#    include <shadow.h>
#  endif /* defined(HAVE_SHADOW_H) */ 
#endif /* defined(SHADOW_PASSWORD) */ 

#if !defined(HAVE_FGETPWENT) /* Some systems (*BSD) don't have fgetpwent... */
#  if defined(HAVE_STRINGS_H)
#    include <strings.h>
#  else /* !(defined(HAVE_STRINGS_H)) */ 
#    include <string.h>
#  endif /* !(defined(HAVE_STRINGS_H)) */ 


struct passwd *bero_getpwnam(const char * name, const char * file);
struct passwd *bero_getpwuid(uid_t uid, const char * file);
#if defined(SHADOW_PASSWORD)
struct spwd *bero_getspnam(const char * name, const char * file);
#endif /*SHADOW_PASSWORD*/

struct passwd *fgetpwent(FILE *stream)
{
	char *entry=(char *) malloc(1024);
	struct passwd *p=(struct passwd *) malloc(sizeof(struct passwd));
	char *tmp,*tmp2;

	if(!fgets(entry,1024,stream)) {
		free(entry);
		free(p);
		return NULL;
	}
	tmp=strdup(entry);
	if(strchr(tmp,':')) {
		*strchr(tmp,':')=0;
		p->pw_name=tmp;
	} else {
		free(tmp); free(entry);	free(p); return NULL;
	}
	tmp2=strchr(entry,':')+1;
	tmp=strdup(tmp2);
	if(strchr(tmp,':')) {
		*strchr(tmp,':')=0;
		p->pw_passwd=tmp;
	} else {
		free(tmp); free(entry); free(p->pw_name); free(p); return NULL;
	}
	tmp2=strchr(tmp2,':')+1;
	tmp=strdup(tmp2);
	if(strchr(tmp,':')) {
		*strchr(tmp,':')=0;
		p->pw_uid=(uid_t) atoi(tmp);
	} else {
		free(tmp); free(entry); free(p->pw_passwd); free(p->pw_name); free(p); return NULL;
	}
	free(tmp);
	tmp2=strchr(tmp2,':')+1;
	tmp=strdup(tmp2);
	if(strchr(tmp,':')) {
		*strchr(tmp,':')=0;
		p->pw_gid=(gid_t) atoi(tmp);
	} else {
		free(tmp); free(entry); free(p->pw_passwd); free(p->pw_name); free(p); return NULL;
	}
	free(tmp);
	tmp2=strchr(tmp2,':')+1;
	tmp=strdup(tmp2);
	if(strchr(tmp,':')) {
		*strchr(tmp,':')=0;
		p->pw_gecos=tmp;
	} else {
		free(tmp); free(entry); free(p->pw_passwd); free(p->pw_name); free(p); return NULL;
	}
	tmp2=strchr(tmp2,':')+1;
	tmp=strdup(tmp2);
	if(strchr(tmp,':')) {
		*strchr(tmp,':')=0;
		p->pw_dir=tmp;
	} else {
		free(tmp); free(entry); free(p->pw_gecos); free(p->pw_passwd); free(p->pw_name); free(p); return NULL;
	}
	tmp2=strchr(tmp2,':')+1;
	if(strchr(tmp2,':')) {
		free(entry); free(p->pw_dir); free(p->pw_gecos); free(p->pw_passwd); free(p->pw_name); free(p); return NULL;
	}
	while(strlen(tmp2) && isspace(tmp2[strlen(tmp2)-1]))
		tmp2[strlen(tmp2)-1]=0;
	p->pw_shell=strdup(tmp2);
	free(entry);
	return p;
}
#endif /* !defined(HAVE_FGETPWENT) - Some systems (*BSD) don't have fgetpwent */


struct passwd *bero_getpwnam(const char * name, const char * file)
{
	FILE *f;
	struct passwd *p;
	struct passwd *r;
	
	if (!strcmp(file,"/etc/passwd")) 
	  return (getpwnam(name));
	f=fopen(file,"r");
	if(f==NULL)
		return NULL;
	p=NULL;
	r=NULL;
	while((r==NULL) && (p=fgetpwent(f)))
		if(!strcasecmp(p->pw_name,name))
			r=p;
	fclose(f);
	return r;
}

struct passwd *bero_getpwuid(uid_t uid, const char * file)
{
	FILE *f;
	struct passwd *p;
	struct passwd *r;
	
	if (!strcmp(file,"/etc/passwd"))
	  return getpwuid(uid);
	f=fopen(file,"r");
	if(f==NULL)
		return NULL;
	p=NULL;
	r=NULL;
	while((r==NULL) && (p=fgetpwent(f)))
		if(p->pw_uid==uid)
			r=p;
	fclose(f);
	return r;
}

#if defined(SHADOW_PASSWORD)
struct spwd *bero_getspnam(const char * name, const char * file)
{
	FILE *f;
	struct spwd *s;
	struct spwd *r;
	f=fopen(file,"r");
	if(f==NULL)
		return NULL;
	s=NULL;
	r=NULL;
	while((r==NULL) && (s=fgetspent(f)))
		if(!strcasecmp(s->sp_namp,name))
			r=s;
	fclose(f);
	return r;
}
#endif /* defined(SHADOW_PASSWORD) */ 

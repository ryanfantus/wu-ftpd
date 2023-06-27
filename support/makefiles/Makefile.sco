#
# Copyright (c) 1999-2003 WU-FTPD Development Group.
# All rights reserved.
# 
# Portions Copyright (c) 1980, 1985, 1988, 1989, 1990, 1991, 1993, 1994 
#    The Regents of the University of California.  
# Portions Copyright (c) 1993, 1994 Washington University in Saint Louis.  
# Portions Copyright (c) 1989 Massachusetts Institute of Technology.  
# Portions Copyright (c) 1998 Sendmail, Inc.
# Portions Copyright (c) 1983, 1995, 1996, 1997 Eric P. Allman.  
# Portions Copyright (c) 1996, 1998 Berkeley Software Design, Inc.  
# Portions Copyright (C) 1991, 1992, 1993, 1994, 1995 1996, 1997 
#    Free Software Foundation, Inc.  
# Portions Copyright (c) 1997 Stan Barber.  
# Portions Copyright (c) 1997 Kent Landfield.
# 
# Use and distribution of this software and its source code are governed by 
# the terms and conditions of the WU-FTPD Software License ("LICENSE").
# 
# If you did not receive a copy of the license, it may be obtained online at
# http://www.wu-ftpd.org/license.html.
# 
# $Id: Makefile.sco,v 1.8 2009/04/19 10:35:42 wmaton Exp $
#

#
# Makefile for SCO Unix
#

CC     = cc
AR     = ar clq
RANLIB = /bin/true
LIBC   = /lib/libc.a
IFLAGS = 
LFLAGS = 
CFLAGS = -O ${IFLAGS} ${LFLAGS}

SRCS   = getusershell.c strcasestr.c strsep.c \
		 authuser.c ftw.c sco.c snprintf.c
OBJS   = getusershell.o strcasestr.o strsep.o \
		 authuser.o ftw.o sco.o snprintf.o

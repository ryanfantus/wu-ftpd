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
# http://www.wu-ftpd.info/license.html.
# 
# $Id: Makefile.sol,v 1.9 2011/10/20 22:58:09 wmaton Exp $
#

DESTDIR=

BINDIR=		${DESTDIR}/usr/sbin
BINOWN=		bin
BINGRP=		bin

SBINDIR=	${DESTDIR}/etc/ftpd
SBINOWN=	bin
SBINGRP=	bin

MANDIR=		${DESTDIR}/usr/share/man
MANOWN=		bin
MANGRP=		bin

INSTALL=	/usr/ucb/install

all:
	@ echo 'Use the "build" command (shell script) to make ftpd.'
	@ echo 'You can say "build help" for details on how it works.'

install: bin/ftpd bin/ftpcount bin/ftpshut bin/ftprestart bin/ftpwho bin/privatepw
	@echo installing binaries.
	@if [ ! -d ${BINDIR} ]; then \
		${INSTALL} -o ${BINOWN} -g ${BINGRP} -m 755 -d ${BINDIR} ; \
	fi
	@if [ ! -d ${SBINDIR} ]; then \
		${INSTALL} -o ${SBINOWN} -g ${SBINGRP} -m 755 -d ${SBINDIR} ; \
	fi
	${INSTALL} -c -o ${SBINOWN} -g ${SBINGRP} -m 110 bin/ftpd        ${SBINDIR}/in.ftpd
	${INSTALL} -c -o ${BINOWN}  -g ${BINGRP}  -m 111 bin/ftpshut     ${SBINDIR}/ftpshut
	${INSTALL} -c -o ${BINOWN}  -g ${BINGRP}  -m 111 bin/ftprestart  ${SBINDIR}/ftprestart
	${INSTALL} -c -o ${BINOWN}  -g ${BINGRP}  -m 111 bin/ftpcount    ${SBINDIR}/ftpcount
	${INSTALL} -c -o ${BINOWN}  -g ${BINGRP}  -m 111 bin/ftpwho      ${SBINDIR}/ftpwho
	${INSTALL} -c -o ${BINOWN}  -g ${BINGRP}  -m 111 bin/privatepw   ${SBINDIR}/privatepw
	@echo installing manpages.
	@if [ ! -d ${MANDIR}/man1 ]; then \
		${INSTALL} -o ${MANOWN} -g ${MANGRP} -m 755 -d ${MANDIR}/man1 ; \
	fi
	${INSTALL} -c -o ${MANOWN} -g ${MANGRP} -m 444 doc/ftpcount.1       ${MANDIR}/man1/ftpcount.1
	${INSTALL} -c -o ${MANOWN} -g ${MANGRP} -m 444 doc/ftpwho.1         ${MANDIR}/man1/ftpwho.1
	@if [ ! -d ${MANDIR}/man5 ]; then \
		${INSTALL} -o ${MANOWN} -g ${MANGRP} -m 755 -d ${MANDIR}/man5 ; \
	fi
	${INSTALL} -c -o ${MANOWN} -g ${MANGRP} -m 444 doc/ftpaccess.5      ${MANDIR}/man5/ftpaccess.5
	${INSTALL} -c -o ${MANOWN} -g ${MANGRP} -m 444 doc/ftpconversions.5 ${MANDIR}/man5/ftpconversions.5
	${INSTALL} -c -o ${MANOWN} -g ${MANGRP} -m 444 doc/ftphosts.5       ${MANDIR}/man5/ftphosts.5
	${INSTALL} -c -o ${MANOWN} -g ${MANGRP} -m 444 doc/xferlog.5        ${MANDIR}/man5/xferlog.5
	@if [ ! -d ${MANDIR}/man1m ]; then \
		${INSTALL} -o ${MANOWN} -g ${MANGRP} -m 755 -d ${MANDIR}/man1m ; \
	fi
	${INSTALL} -c -o ${MANOWN} -g ${MANGRP} -m 444 doc/ftpd.8           ${MANDIR}/man1m/ftpd.1m
	${INSTALL} -c -o ${MANOWN} -g ${MANGRP} -m 444 doc/ftpshut.8        ${MANDIR}/man1m/ftpshut.1m
	${INSTALL} -c -o ${MANOWN} -g ${MANGRP} -m 444 doc/ftprestart.8     ${MANDIR}/man1m/ftprestart.1m
	${INSTALL} -c -o ${MANOWN} -g ${MANGRP} -m 444 util/privatepw/privatepw.8     ${MANDIR}/man1m/privatepw.1m

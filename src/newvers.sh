#!/bin/sh -
#
# Copyright (c) 1999-2003 WU-FTPD Development Group.  
# All rights reserved.
#  
# Portions Copyright (c) 1980, 1985, 1988, 1989, 1990, 1991, 1993, 1994  
#   The Regents of the University of California. 
# Portions Copyright (c) 1993, 1994 Washington University in Saint Louis.  
# Portions Copyright (c) 1996, 1998 Berkeley Software Design, Inc.  
# Portions Copyright (c) 1989 Massachusetts Institute of Technology.  
# Portions Copyright (c) 1998 Sendmail, Inc.  
# Portions Copyright (c) 1983, 1995, 1996, 1997 Eric P.  Allman.  
# Portions Copyright (c) 1997 by Stan Barber.  
# Portions Copyright (c) 1997 by Kent Landfield.  
# Portions Copyright (c) 1991, 1992, 1993, 1994, 1995, 1996, 1997  
#   Free Software Foundation, Inc.    
#  
# Use and distribution of this software and its source code are governed   
# by the terms and conditions of the WU-FTPD Software License ("LICENSE").  
#  
# If you did not receive a copy of the license, it may be obtained online  
# at http://www.wu-ftpd.info/license.html.  
#
# $Id: newvers.sh,v 1.15 2016/03/10 11:20:46 wmaton Exp $
#
if [ ! -r edit ]; then echo 0 > edit; fi
touch edit
if [ -d CVS -o -f .prerelease ]; then
awk '	{	edit = $1 + 1; }\
END	{	printf "char version[] = \"Version wu-2.8.0-CC5-prerelease(%d) ", edit > "vers.c";\
#LANG=
#LC_TIME=
		printf "%d\n", edit > "edit"; }' < edit
else
awk '	{	edit = $1 + 1; }\
END	{	printf "char version[] = \"Version wu-2.8.0-CC5(%d) ", edit > "vers.c";\
#LANG=
#LC_TIME=
		printf "%d\n", edit > "edit"; }' < edit
fi
echo `LC_TIME=C date`'";' >> vers.c
echo 'char wu_name[] = "wu-ftpd";' >> vers.c
echo 'char wu_number[] = "2.8.0-CC5";' >> vers.c

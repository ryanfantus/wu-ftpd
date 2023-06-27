Summary: An FTP daemon originally developed by Washington University.
Name: wu-ftpd

%define ver 2.8.0

Version: %{ver}
# Release is set to 3 because there's another wu-ftpd RPM
# out there that's actually based on the 2.7.0 code "release", 
# but labeled as version 2.8.0-2. The CC2 source package is
# definitely newer, and seems more polished and complete.
Release: 3
License: BSD
Vendor: wu-ftpd.info
Group: System Environment/Daemons
URL: http://www.wu-ftpd.info
Source: ftp://ftp.wu-ftpd.info/pub/wu-ftpd/wu-ftpd-%{ver}-CC2.tar.gz
Patch0: wu-ftpd-2.8.0-owners.patch
Packager: Canadian Contingent wuftpd@ottix.net
Requires: xinetd, /etc/pam.d/system-auth
# If including TLS support
#Requires: xinetd, /etc/pam.d/system-auth, openssl
Provides: ftpserver, BeroTFTP
Obsoletes: BeroFTP
BuildRequires: fileutils, pkgconfig
# If including TLS support
#BuildRequires: fileutils, pkgconfig, openssl-devel
Buildroot:  %{_tmppath}/%{name}-root

%description
The wu-ftpd package contains the wu-ftpd FTP (File Transfer Protocol)
server daemon.  The FTP protocol is a method of transferring files
between machines on a network and/or over the Internet.  Wu-ftpd's
features include logging of transfers, logging of commands, on the fly
compression and archiving, classification of users' type and location,
per class limits, per directory upload permissions, restricted guest
accounts, system wide and per directory messages, directory alias,
cdpath, filename filter and virtual host support.

Install the wu-ftpd package if you need to provide FTP service to remote
users.

%prep
# Quietly unpack the source to a working directory
%setup -q -n wu-ftpd-%{ver}-CC2
# Apply "owners" patch to remove root-only ownership changes from source
# and allow regular user to build RPM.
%patch0 -p1 -b .owners
# Just in case someone forgot
find . -type d -name CVS |xargs rm -rf

#if pkg-config openssl ; then
#    CFLAGS="$RPM_OPT_FLAGS `pkg-config --cflags openssl`"; export CFLAGS
#    LDFLAGS=`pkg-config --libs-only-L openssl` ; export LDFLAGS
#else
    CFLAGS="$RPM_OPT_FLAGS"; export CFLAGS
#fi

#  Common configure flags:
#
# --disable-dnsretry    don't retry failed DNS lookups
# --disable-quota       don't add quota support, even if OS supports it
# --disable-anonymous   don't allow anonymous ftp access
# --enable-ls           enable internal ls command
# --disable-mail        don't allow mail on upload
# --disable-rfc931      don't do RFC931 lookups
# --enable-passwd       support alternative passwd/shadow files
# --enable-pam          enable PAM authentication (requires PAM libs)
# --disable-closedvirt  allow guests to log in to a virtual server
# --enable-ipv6         enable ftp IPv6 extensions
# --enable-tls          enable TLS security
# --enable-tls-debug    enable TLS debug
# --enable-gssapi       enable GSSAPI security extensions
# --enable-mit-gssapi   Try to find the GSSAPI libraries from the MIT Kerberos
%configure --disable-dnsretry --disable-quota --disable-anonymous \
    --enable-ls --disable-mail --disable-rfc931 --enable-passwd \
    --enable-pam --disable-closedvirt --enable-ipv6

%build
make all

%install
rm -rf $RPM_BUILD_ROOT
mkdir -p $RPM_BUILD_ROOT/etc \
    $RPM_BUILD_ROOT/etc/xinetd.d \
    $RPM_BUILD_ROOT/etc/pam.d \
    $RPM_BUILD_ROOT/etc/logrotate.d \
    $RPM_BUILD_ROOT%{_sbindir} \
	$RPM_BUILD_ROOT/usr/share/man/man{1,5,8}
# Extra ROOT var is for compatibility with some Makefiles that
# use this name instead of DESTDIR.
make install DESTDIR=$RPM_BUILD_ROOT ROOT=$RPM_BUILD_ROOT
install -m 755 util/xferstats $RPM_BUILD_ROOT%{_sbindir}
cd doc/examples
install -m 600 ftpusers ftphosts ftpgroups ftpaccess $RPM_BUILD_ROOT/etc
install -m 644 ftpconversions $RPM_BUILD_ROOT/etc
strip $RPM_BUILD_ROOT%{_sbindir}/* || :
ln -sf in.ftpd $RPM_BUILD_ROOT%{_sbindir}/wu.ftpd
ln -sf in.ftpd $RPM_BUILD_ROOT%{_sbindir}/in.wuftpd
cat > $RPM_BUILD_ROOT/etc/pam.d/ftp <<EOF
#%PAM-1.0
auth    required pam_listfile.so item=user sense=deny file=/etc/ftpusers onerr=succeed
auth    required pam_pwdb.so shadow nullok
auth    required pam_shells.so
account required pam_pwdb.so
session required pam_pwdb.so
EOF
chmod 644 $RPM_BUILD_ROOT/etc/pam.d/ftp
cat > $RPM_BUILD_ROOT/etc/logrotate.d/ftpd <<EOF
/var/log/xferlog {
    # ftpd doesn't handle SIGHUP properly
    nocompress
    minsize 100K
}
EOF
chmod 644 $RPM_BUILD_ROOT/etc/logrotate.d/ftpd
cat > $RPM_BUILD_ROOT/etc/xinetd.d/wu-ftpd <<EOF
service ftp
# default: on
# description: wu-ftpd 2.8.0-3 FTP server
{
    disable         = no
    socket_type     = stream
    protocol        = tcp
    wait            = no
    nice            = 10
    user            = root
    server          = /usr/sbin/in.ftpd
    server_args     = -a -l -i -o -t 300 -T 300 -w
    log_on_success  += DURATION HOST USERID
}
EOF
chmod 644 $RPM_BUILD_ROOT/etc/xinetd.d/wu-ftpd

%clean
rm -rf $RPM_BUILD_ROOT

%post
# Do this here instead of the install stanza because we never want to 
# overwrite this log, and if its not present, then it should be a 
# zero-byte file to start with.
if [ ! -f /var/log/xferlog ]; then
    touch /var/log/xferlog
    chmod 600 /var/log/xferlog
fi

# Install certificate for TLS/SSL
#cd /usr/share/ssl
#if [ ! -e certs/ftpd-rsa.pem ]; then
#    (echo US
#    echo .
#    echo .
#    echo .
#    echo .
#    echo .
#    echo .) |openssl req -newkey rsa:1024 -nodes -out certs/ftpd-rsa.pem \
#    -x509 -days 365 -keyout private/ftpd-rsa-key.pem &>/dev/null
#fi

/sbin/service xinetd reload > /dev/null 2>&1 || :

%postun
/sbin/service xinetd reload > /dev/null 2>&1 || :

%files
%defattr(-,root,root)
%config(noreplace) /etc/xinetd.d/wu-ftpd
%doc README CHANGES ERRATA CONTRIBUTORS COPYRIGHT LICENSE
%doc doc/misc doc/examples doc/HOWTO
%config(noreplace) /etc/ftp*
%config(noreplace) /etc/pam.d/ftp
%config(noreplace) /etc/logrotate.d/ftpd
%{_mandir}/*

%defattr(0755,bin,bin)
%{_sbindir}/*
%{_bindir}/*

# CHANGES log: There are actually two different change logs here.
# The changelog from RedHat, who supported and backported wu-ftpd 
# until version 2.6.2-12, and the (non-RPM) changelog from the CC 
# guys and others who took on renewed support of wu-ftpd.org after 
# it languished for sometime. For better or worse, they are merged
# here.

%changelog
* Fri May 20 2011 Austin Ellis <aellis -at- kodiaknetworks.com>
- Spec rewritten and CC2 source built for RHEL6

* Fri Jun 26 2009 Changes in 2.8.0-CC2:

- Cleaned-up and updated the ftpd.8 manpage which had languished for
    some time.

- Added Auto tuning/auto buf, with added commands SITE BUFSIZE and
    SITE BUFSIZEMEASURE.  Use --enable-autobuf to enable this feature.
    Based on a patch on work done on WU-FTPD-2.6.1 by Gaurav Navlakha, et al
    of DAST, NLANR (now CAIDA).  This code also contains the ability to
    report back on buffer usage.  Note that an autobuf client needs to
    be used to take advantage of this feature.  For the time being, the
    code for buffer measurement is IPv4 only.

- Updated src/extensions.c to take into account a change in Linux quota
    structure.  Based on a patch by Chris Butler.

- Added 'quiet' option to util/xferstats based on Debian bug #307152.
    Also included a new xferstats(8) man page based on Debian bug #10332.

- src/ftpcount.c's test of LINUX but not Redhat 6.0 removed and a call
    to 'ps' has been modified.  Based on a patch by Chris Butler.

- src/glob.c modified to permit "LIST ." as per Debian bug #101847.

- Update several Makefile.in files with datarootdir = @datarootdir@, 
    regenerate configure using the latest GNU autotools.  Also added newer
    versions of config.guess and confg.sub as hinted at by Debian bug
    num 356519.

- As hinted at by Chris Butler's patches to a couple of man pages, 
    headers really should by uppercase.  All man pages are now consistently
    formatted with this in mind.

- The following FreeBSD patches have been incorporated to one extent
    or another:

	- patch-aa:	OPIE update (again to src/ftpd.c)
	- patch-ae:	OPIE update (src/config/config.fbs)
	- patch-af:	Modify strcasestr (support/strcasestr.c)
	- patch-aj:	Modify strcasestr (src/proto.h)
	- patch-al:	Modify strcasestr (support/makefiles/Makefile.fbs)
	- patch-am:	OPIE update (src/makefiles/Makefile.fbs)
	- patch-ar:	OPIE update (configure.in)

    All patches were taken from:
	http://www.freebsd.org/cgi/cvsweb.cgi/ports/ftp/wu-ftpd/files/

- Access classes may now be individually restricted by time. For example
    one can write a timeout clause like this:
	timeout idle 1800 anon-local
    This instructs the daemon to enforce an idle timeout of 1800 seconds
    on just the anon-local access class.  Any combination or permutation
    can be used between the standard timeouts and the access classes you
    create.  Based on a patch by Sylvain Goulart of the National Research
    Council of Canada applied to src/timeout.c.

- Patch by John Sutton of SCL Internet to set default behaviour of
    internal ls to ls -la.  Applied to src/ftpd.c.  This will allow users
    to see hidden files as well.

- Acknowledge bugfix to internal ls provided by "sashi" via his blog.
    Applied to src/ftpd.c.

- Patch by John Sutton of SCL Internet to src/tlsutil.c to simplify
    some TLS code involving calling vfprintf.  The patch uses tls_vfprintf
    instead.

* Wed Apr 22 2009 Changes in 2.8.0-CC1:

- Add '--' to doc/examples/ftpconversions to appropriate commandlines
    to stop hacking via ftpconversion downloads.  Based on a Debian and
    FreeBSD patch.

- Fix MAIL_ADMIN vulnerability which points to an error within SockPrintf
    function. [SECURITY CVE-2003-1327]

- Fix S/KEY buffer overflow in key_challenge function in ftpd.c. 
    [SECURITY CVE-2004-0185]

- Fix MAXPATHLEN calculation bug that can trigger a vulnerability.
    [SECURITY CVE-2003-0466]

- Fixed to stop real users from bypassing restricted-uid and restricted-gid
    restrictions. [SECURITY CVE-2004-0148]

- Direct DNS lookups using the resolver library replaced by use of the
    system's name service (by calling gethostbyaddr/getnameinfo and
    gethostbyname/getaddrinfo). Code donated by Sun Microsystems.

- Scalability and transfer logging enhancements, code donated by Sun
    Microsystems. New ftpaccess clauses:

        flush-wait yes|no [<typelist>]
        ipcos control|data <value> [<typelist>]
        quota-info <uid-range> [<uid-range> ...]
        recvbuf <size> [<typelist>]
        rhostlookup yes|no [<addrglob> ...]
        sendbuf <size> [<typelist>]
        xferlog format <formatstring>

    ipcos replaces iptos. New ftpd -h option added to enable host limits.
    New ftpd -4 option added to make the standalone server listen for
    connections on an AF_INET type socket (useful when built with IPv6
    support). New -v options added to ftpcount and ftpwho to support
    virtual hosts.

- Modified configure to insert the correct paths into the doc/*.5 files.
    Modified configure to incorporate doc/Makefile for future uses.
    Modified configure remove the "build" help file, .bld.hlp.
    Modified the 'build' script to insert paths in the references
    for FTPLIB for the doc/*.5 files.

- Changed Copyright headers to 
       'Copyright (c) 1999-2003 WU-FTPD Development Group.'

- Changed strcpy and strncpy calls to strlcpy where appropriate.  Changed 
    sprintf calls to snprintf where appropriate.  Changed strcat calls to 
    strlcat where appropriate. Added strlcat.c and strlcpy.c and supporting
    man page to libsupport.a. Modified configure to test for strlcpy and
    strlcat availability and include it in libsupport.a if needed.

- Fixed active mode connect retry denial of service vulnerability.
    [SECURITY CVE-2003-1329]

- GSS-API, RFC 2228 support added, code donated by Sun Microsystems.

- Fixed a problem which allowed file globs with series of stars to hang
    the server.  In fixpath, reduce all series of stars to a single star.

- Fixed dir_check and upl_check so they deny access if they can't stat
    the current working directory.  This effects the DELE command (when
    deleting a directory), MKD, RMD, STOR, APPE, and STOU when using "*"
    wildcards on the upload clause.

- When expanding ~username, only do the special "/./" processing if the
    logged in user is a guest.

- Added option --with-facility=x to configure for specifying the syslog
    facility.

- Added the missing -x option to the ftpd getopt() string and to ftpd.8.

- STOU should not require a parameter.  In fact, it should not allow one.
    Since it traditionally has, WU-FTPD will allow it as an optional
    parameter.

- defumask <umask> parsing made consistent with ftpd -u umask parsing, a
    leading 0 is no longer required to signify octal and the umask must only
    contain octal digits and be <= 0777.

- Nick Maclaren <nmm1@cam.ac.uk> submitted patches to prevent certain
    sequences from anonymous users gaining elevated privileges.  Also a bugfix
    to throughput limiting when there's an error in the ftpaccess file.

- doenges@lpr.e-technik.tu-muenchen.de provided corrections for Compaq
    (DEC) Tru64 Unix.  His comment: uploading of files by anonymous users
    failed with permission problems if the uid of the ftp daemon did not match
    the uid the file was supposed to belong to (as set in ftpaccess with the
    upload keyword). 

- fish@daacdev1.gsfc.nasa.gov provided corrections for IRIX (sgi) support.

- TLS, IETF Draft draft-murray-auth-ftp-ssl-07, support added, code donated
    by IBM.

- SIZE command in ASCII mode was consuming CPU. The solution is to return 
    a 504 error reply for all SIZE requests when in ASCII mode. 

- Added support for utmp logging.  This should work for most systems,
    but YMMV; check src/config if you have problems, it's most likely the
    pathname.  Submitted by d.stolte@tu-bs.de.

- Separated data connection timeout errors from others.  From a patch by
    Joe Laffey <joe@laffeycomputer.com> which prevented segmentation faults
    on a timeout on the data conection.  The segfault was already fixed, but
    separating the response sounded like a good idea anyway.

- Changed anonymous password examples so they don't fail validation. Changed
    rfc822 validation not to allow "joe@" (as "joe@hostname" isn't allowed).

- IPv6, RFC 1639 (LPRT/LPSV) and RFC 2428 (EPRT/EPSV) support added,
    code donated by Sun Microsystems.

- Many corrections to large file support (use of off_t and L_FORMAT).

- Cleaned up the ambigious if/if/else statements by adding braces.

- Modified commented comments so some compilers would not throw off warnings.

- Changed the default CheckMethod to POSIX and changed the paths to
    /usr/bin/md5sum and /usr/bin/cksum (from /bin).

- Fixed off by 1 error in limit_time calculation.

- Restored the 2.6.0 behavior where the size of a file transfered is only
    used in data_limit calculations after its been transfered (the size of a
    file produced by a conversion isn't known in advance).

- Spurious home directory restrictions would occur if the user did not
    have permission to read their own home or one of its parent
    directories.

- Still MORE changes to ftpaccess parsing.  All looping parses now
    continue past missing parameters instead of stopping unexpectedly.

- When using PAM, the anonymous user (ftp) can be authenticated but may
    not be known to the local system.  If this occurs, try the "nobody"
    user.  If neither exists, log a suitable message and kill the session.
    This should probably be done for other network-based authentication
    methods: patches would be very welcome.

- Treat ASCII CR (\r) as white space in the fptaccess file.  Done the
    Wrong Way but good enough to prevent most problems when a clueless
    admin uses Windows Notepad to edit the file instead of a real editor
    like emacs or vi.

- New ftpaccess clause "iptos" to allow management of IP Type Of Service
    for both control and data connections.  Note: the default IPTOS changes
    to use the same TOS as previous versions you must add the following to
    your ftpaccess:

        iptos control lowdelay
        iptos data throughput

    See the ftpaccess manpage for a full description of these options.

- Guestserver clause with no parameters hangs the control socket.

- New ftpaccess clauses "signoff" and "stat" work similar to "greeting".
    Please read the ftpaccess man page for more information on these new
    options.

- Log security issue on denied umask and chmod.

- Properly log security issue if RMD is denied because deletes are not
    allowed for this user.

- Restricted users should be allowed to use chmod and umask as well as
    SITE GROUP and SITE GPASS, but still cannot use SITE EXEC and SITE
    INDEX.

- Make y/n for chmod, umask, chmod, delete, overwrite case-insensitive.

- Correct chmod, umask, overwrite and rename to match documented
    operation.  Namely, anonymous users cannot use them and all other can.

- Avoid crashes on certain configuration problems by making parameters
    optional and choosing reasonable defaults.  Effected clauses are:
        private (default is no)
	log commands (default is log commands for all users)
        log transfers (default to log all transfers)
        log security (default to log all issues)
        compress (default to allow compression/uncompression)
        tar (default to allow tar on-the-fly)
    Also, ignore without crashing on banner clause without a pathname.

- In fixpath(), don't remove a trailing '.' at the end of the path.  From
    John Simmons <jbsimmon@us.ibm.com>.

- If using OPIE, don't accept regular passwords if OPIE tells us not to.
    From Ken Mort <ken@mort.net>.

- Added optional parameters to the upload clause.  Newly created
    directories can now be given user/group ownership different than newly
    created files.

- For autoconf, some systems define __SVR4 and not SVR4.  So, in
    src/config.h.in, if we see __SVR4 and not SVR4, go ahead and define
    SVR4.  Solaris is the most-cited culprit here, but there may be
    others.  The old build configs specifically define SVR4 so they
    have no problems.

- Add support for tcpwrappers in standalone daemon mode.  Read the
    comments at the end of src/config.h.noac for instructions on how
    to enable them.

- Add logging of restart point and actual byte count in the xferlog.
    Since this will break xferstats and other llog analyzers, it is
    disabled by default.

- Add To: and Date: headers for upload notification emails.  Note the
    Date: header is *always* in UTC.  If someone wants to change it to
    local time with a correct UTC offset, send the patch along.

- Update ftpaccess manpage to better describe lslong, lsshort and
    lsplain.

- Fix passive ports, missing ntohl() call caused misinterpretation.

- Document logfile ftpaccess option.  Promote it to be usable in all
    configurations instead of just new-style virtual hosts (with
    /etc/ftphosts existing).

- Fix crash following timeout on a data connection.

- Add an option to track logins via the lastlog file. This option is
    enabled by default.  [patch by Sylvain Robitaille]

- Add user= to work similarly to class=; this also fixes a long-standing
    problem with class=.  Things should now work a bit more like we'd
    expect when you use class=.

- Add throughput rate limiting to ASCII-mode file transfers.  For some
    reason it was only applied to binary transfers.

- Use mkstemp() and mktemp() for temp file creation in privatepw if those
    functions are available

- Fix so virtual hosts work with the standalone daemon.

- Add an option to define an alternate home directory to log real users
    into if we're doing strict_homedir checking or base_homedir checking
    and we fail either one of those.  [patch by Sylvain Robitaille]

- Split up the PARANOID configuration option into individual options
    for finer control.  [patch by Sylvain Robitaille]

- Add an option to check a user's home directory against a "base"
    directory and refuse the login if the former isn't below the
    latter.  [patch by Sylvain Robitaille]

- Renamed support/ftw.h to support/wuftpd_ftw.h to ensure the system ftw.h
    is used when HAVE_FTW is defined.

- Changed the way support headers are included to work with VPATH.

- Added required fflush() call between input and output, necessary when a
    file using stdio is opened in update mode. email on anonymous upload now
    works on Solaris and AIX.

- Send a 502 reply instead of a 500 in disabled SITE commands.

- Fixed command and transfer logging so -L, -i and -o work with -a.

- Someone moved the call to get quota data earlier in the msg_massage
    function.  This little optimization causes a segfault.  Rather than
    reverse the change, just output "[unknown]" when quota information
    is desired and not yet available (for instance in the initial banner).

- Added host-limit configuration which enables the limiting of the
    number of sessions from one IP.

- Added NO_UTMP #ifdefs for systems that don't have a wtmp file.

- Improved the error reporting in ftpshut, ftprestart and ftpcount.

- Send a 502 reply instead of a 425 when PASV support is disabled.
    Send 502 instead of 500 when PORT is disabled.

- Two PASV commands in the same second get the same port assigned.
    Add some salt to spice things up.

- Host matching on the class clause and elsewhere used to allow []
    ranges as well as wildcards.  They are now allowed once more.

- Off-by-one in wu_fnmatch caused problems parsing [] ranges.

- Fix a segfault if there's a typo on pasv-allow.  For instance,
    "pasv-allow all *" instead of "pasv-allow all 0.0.0.0/0".  To be
    save, for NOMATCH result instead of allowing the PASV connection.

- If using restricted-uid and the user's home includes symlinks, the
    PWD command can cause a crash.  Run both paths through realpath to
    fix this.

- guestserver should deny anonymous access with no parameters.

- When using OPIE, don't require an OPIE reply if the user does not
    have an opie key.

- Don't lose last character when STOU exceeds 9 probes to find a
    unique filename.

- When using OPIE, don't allow normal passwords when OPIE is
    required.

- On command-line -u option, don't allow non-octal digits.  Doh.

- Need HAVE_QUOTACTL on IRIX.

- In src/extensions.c is a definition of snprintf.  If needs to be
    protected by HAVE_SNPRINTF.

- SunOS really doesn't have a working fchdir().

- NLST should not send the names of dangling symlinks since they can
    not be retrieved.

- guestuser and guestgroup no longer make anonymous users into guests
    when matching wildcards and ranges.

- Corrected an information leak when failing a MKD with restricted-uid.
    The pathname reported in the error needs to have the user's home
    stripped off the error reply.  From Richard Mirch <mirchr@sunyit.edu>

- AIX 4.1.x needs libbsd.a & libs.a.

- Added definition for AIX's file system (JFS).

- AIX 4.1.x has getrlimit() but no RLIMIT_NOFILE. It does have
    gettablesize().

- Fixed a problem with the order of the includes of sys/mnttab.h and
    sys/mntent.h. Solaris has them both but only defines struct mnttab.

- IRIX has no NCARGS in the system's include files but defines it in the
    kernel ('systune ncargs' outputs: ncargs = 20480 (0x5000)).

- Local quota updates can now be seen during the session. Two exceptions:
    1) It wont work in a chroot() environment unless the quota DB can be
       accessed there.
    2) WU-FTPD does not support displaying of files with cookies more than
       once. So the current solution is to display different files in
       different places (in example cd to other directories).

- Fixed file descriptor and memory leaks in the email on anonymous upload
    code.

- Michael Brennen has contributed the Guest HOWTO to the project.  It is
    now located in the doc/HOWTO section and will be included in all
    future releases.

- Off-by-one and missing step-increment in a couple routines for
    throughput limiting.

* Mon Jul 28 2003 Thomas Woerner <twoerner@redhat.com> 2.6.2-12
- bugfix release CAN-2003-0466 off-by-one

* Thu Jul 24 2003 Changes in 2.7.0: Never released
There WAS no version 2.7.0 released.  During development a vendor
inadvertently released a 2.6.1 version based upon the 2.7.0 CVS development
snapshot.  That version released contained the security problems addressed
by version 2.6.2, but internally claimed version 2.7.0.  To avoid confusion
version 2.7.0 was not released, and the development version was renumbered
to version 2.8.0.  The following changes are listed here to reflect the
steps taken to help prevent this from recurring:

- Changed newvers.sh to check for the existance of the directory CVS or a
    ".prerelease" file in the src directory.  If either is present this is
    assumed to be a prerelease version of the software and the version
    number indicates this.  For example, "wu-2.8.0-prerelease".  This isn't
    perfect, but it should help.

- Changed 'build distrib' to check for the existance of CVS and create
    src/.prerelease if it is present.  Also updated the target to match the
    current directory layout and the fact we use CVS and not RCS, so it's
    usable once again.

* Fri Apr  4 2003 Thomas Woerner <twoerner@redhat.com> 2.6.2-11
- added noreplace for config files

* Tue Jan  7 2003 Nalin Dahyabhai <nalin@redhat.com> 2.6.2-10
- rebuild

* Fri Jan  3 2003 Nalin Dahyabhai <nalin@redhat.com>
- if pkg-config "knows" about OpenSSL, use its cflags and libs-only-L flags

* Mon Nov 11 2002 Nalin Dahyabhai <nalin@redhat.com> 2.6.2-9
- remove directory names from the pam config file, allowing it to work equally
  well for any arch on multilib boxes

* Fri Aug 23 2002 Tim Waugh <twaugh@redhat.com> 2.6.2-8
- Fix %%post scriptlet (bug #70525).

* Fri Jun 21 2002 Tim Powers <timp@redhat.com> 2.6.2-7
- automated rebuild

* Thu May 23 2002 Tim Powers <timp@redhat.com> 2.6.2-6
- automated rebuild

* Tue Mar 12 2002 Bernhard Rosenkraenzer <bero@redhat.com> 2.6.2-5
- Don't do identd lookups on connection (#60708)

* Mon Mar  4 2002 Bernhard Rosenkraenzer <bero@redhat.com> 2.6.2-4
- Rebuild in current environment
- Fix source tarball, it was way too large

* Thu Feb 14 2002 Bernhard Rosenkraenzer <bero@redhat.com> 2.6.2-3
- Fix bugs #57631, #59266, #57566

* Wed Jan 09 2002 Tim Powers <timp@redhat.com>
- automated rebuild

* Thu Dec 13 2001 Bernhard Rosenkraenzer <bero@redhat.com> 2.6.2-1
- Update codebase
- Fix #57231
- Chroot users by default (RFE#53376)
- Build IPv6 and TLS support

* Thu Nov 29 2001 Changes in 2.6.2:
- Added checks for missing "]" and "}" in filename globs, this completes
    the file globbing heap corruption vulnerability fix.
- Added checks to the globbing code for overflow of restbuf, and additional
    globerr setting and checking to speed up return on error.
- Changed the globbing code to use qsort, much faster when sorting a large
    number of strings.
- Handle ftpglob() returning a vector containing just a NULL string, fixes
    problems caused by CWD ~{
- Somehow the fix for pasv-allow didn't actually make it into 2.6.1
- Provide a compile-time option to revert NLST to showing directories.
- Fix missing format strings in debugging code.

* Wed Nov 21 2001 Bernhard Rosenkraenzer <bero@redhat.com> 2.6.1-20
- Improve the fix

* Tue Nov 20 2001 Bernhard Rosenkraenzer <bero@redhat.com> 2.6.1-19
- Fix security bug in ftpglob

* Tue Jun 26 2001 Bernhard Rosenkraenzer <bero@redhat.com> 2.6.1-18
- Remove a couple of CVS admin files from the docs (#44921)

* Thu May 31 2001 Bernhard Rosenkraenzer <bero@redhat.com> 2.6.1-17
- Update to current CVS stable branch

* Wed Mar 28 2001 Bernhard Rosenkraenzer <bero@redhat.com>
- Add fix for 2 possible DoS attacks from CVS.
- Fix #31158

* Tue Mar  6 2001 Bernhard Rosenkraenzer <bero@redhat.com>
- Hack in support for large files (#30693)

* Fri Mar  2 2001 Bernhard Rosenkraenzer <bero@redhat.com>
- Add fixes from current 2.6.2 branch, fixes insecure tempfile
  creation in privatepw

* Tue Feb 27 2001 Preston Brown <pbrown@redhat.com>
- noreplace xinetd.d file

* Sat Jan 20 2001 Bernhard Rosenkraenzer <bero@redhat.com>
- Adapt /etc/ftpconversions to current anonftp (3.1-1)
- Remove the unused rhsconfig/ftpaccess file

* Fri Jan 12 2001 Bernhard Rosenkraenzer <bero@redhat.com>
- Set /etc/ftpaccess to more sane default settings,
  add comments on modifying the file
  Bugs #23744, #23745

* Wed Jan 10 2001 Bernhard Rosenkraenzer <bero@redhat.com>
- Add URL tag (#22986)

* Fri Dec 01 2000 Trond Eivind Glomsrød <teg@redhat.com>
- make sure it's turned off by default

* Wed Oct 18 2000 Bernhard Rosenkraenzer <bero@redhat.com>
- Change the ftpaccess file to more secure defaults

* Thu Oct  5 2000 Bernhard Rosenkraenzer <bero@redhat.com>
- enable internal ls (experimental features are ok for rawhide...)
  The feature needs testing and seems relatively stable now.
- disable DNS retries (Bug #8149)

* Wed Aug  9 2000 Bernhard Rosenkraenzer <bero@redhat.com>
- --disable-ls, we shouldn't keep experimental features in a release.

* Sun Jul 23 2000 Nalin Dahyabhai <nalin@redhat.com>
- fix strange listing data bug (#13752)
- run make during the %%build phase

* Tue Jul 18 2000 Bill Nottingham <notting@redhat.com>
- add description & default to xinetd file

* Fri Jul 14 2000 Jeff Johnson <jbj@redhat.com>
- correct man page references (#12930).

* Thu Jul 13 2000 Prospector <bugzilla@redhat.com>
- automatic rebuild

* Sun Jul  2 2000 Changes in 2.6.1:
- Fix security leaks that could result in a root shell compromise.
- Fix memory leaks in internal ls (this feature still needs more testing;
    you should probably not use it on high-traffic production servers yet.)
- Fix up the port-allow command in ftpaccess.
- Merge in the virtual passwd/virtual shadow features of BeroFTPD.
- Some fixes to the configure script.
- SITE MINFO was missed in 2.6.0 when disabling SITE NEWER.
- Fix documentation of data-limit.

* Sat Jul  1 2000 Bernhard Rosenkraenzer <bero@redhat.com>
- 2.6.1
- get rid of most of our patches; they're in 2.6.1.

* Fri Jun 23 2000 Bernhard Rosenkraenzer <bero@redhat.com>
- fix the security bugfix

* Fri Jun 23 2000 Bernhard Rosenkraenzer <bero@redhat.com>
- fix security bug w/ SITE EXEC

* Thu Jun  1 2000 Nalin Dahyabhai <nalin@redhat.com>
- Modify PAM configuration to use system-auth
- Miscellaneous FHS fixes

* Mon May 22 2000 Trond Eivind Glomsrød <teg@redhat.com>
- Add /etc/xinetd.d/wu-ftpd

* Sat May 20 2000 Bill Nottingham <notting@redhat.com>
- use normal getpwnam/getpwuid for standard password files (for NIS, etc.)

* Sun Mar 26 2000 Florian La Roche <Florian.LaRoche@redhat.com>
- make binaries readable

* Mon Mar 13 2000 Bernhard Rosenkraenzer <bero@redhat.com>
- recompile

* Fri Mar 10 2000 Bernhard Rosenkraenzer <bero@redhat.com>
- fix bug in configure script

* Sun Mar  5 2000 Bernhard Rosenkränzer <bero@redhat.com>
- remove the conflict between PAM and alternative passwd files and enable PAM

* Sun Mar  5 2000 Bernhard Rosenkränzer <bero@redhat.com>
- fix up behavior for missing entries in shadow password files when the
  non-shadow password file contains all info.
  This fixes the MD5 problem.
- remove the nlstbug patch; it's now included in the bero patch.

* Mon Feb 28 2000 Bernhard Rosenkränzer <bero@redhat.com>
- fix up NLST behavior on broken symlinks

* Sat Feb 12 2000 Bernhard Rosenkränzer <bero@redhat.com>
- Merge some features from BeroFTPD people requested:
  - alternate passwd/shadow files for virtual hosts
  - ratios
- switch to using autoconfed build - it's much better on linux.
  build makes some faulty assumptions based on its glibc 2.0 and
  kernel 2.0.x knowledge.

* Fri Feb  5 2000 Bernhard Rosenkränzer <bero@redhat.com>
- fix a bug (the port-allow ftpaccess option was broken)
- handle compressed man pages

* Thu Oct 21 1999 Cristian Gafton <gafton@redhat.com>
- version 2.6.0, but no autoconf yet

* Mon Oct 18 1999 Changes in 2.6.0:

- On sigpipe, always log a lost connection.
- Added a log message on attempts to download files marked unretrievable.

- The SITE NEWER feature has been disabled.  A compile-time option has been
    added to re-enable it.  See config.h.noac for more information on this.

- With restricted-uid/gid, CWD to a non-existant directory would display the
    full pathname rather than just relative to the user's home.  Actually, the
    fix catches most cases where this could occur, not just the CWD verb.

- Fixed a bug in the restricted-uid/gid feature which could allow access
    outside the user's home directory in some cases.

- Bumped MAXHST (max. hosts allowed on a line) for ftphosts from 10 to 12.
    Fixed a bug related to this which can cause the server to crash checking
    host access.

- The internal ls (see below) was judged to be unready.  It has been disabled
    by default but can be enabled with a compile-time option for those who wish
    to attempt to debug it (be warned, it has a lot of problems).

- Split the "bad shell or user not in ftpusers" syslog message into two
    messages to prevent confusion.

- Filename globs for LIST, NLST and SITE EXEC, as well as a few internal
    uses, are cleaned up before processing.  For example: */./../* becomes
    just *.  This prevents certain memory starvation DoS attacks.

- Corrections for RFC compliance can break some clients.  If possible, the
    broken client should be updated, but a compile-time option has been
    added.  See the config.h.noac for more information on this.

- Created doc/HOWTO directory and moved VIRTUAL.FTP.SUPPORT and 
    upload.configuration.HOWTO there.

- Add a README.AUTOCONF file describing the autoconf build in detail.

- UC, Berkeley, has removed the requirement that all advertising material
    must include credit to them.  Removed the clause from the LICENSE and
    the historical licenses in the COPYRIGHT file.

- Added the email-on-upload feature from BeroFTPD.  See the ftpaccess man
    page for defaults on these added ftpaccess clauses:

        mailserver <hostname>
        incmail <emailaddress>
        mailfrom <emailaddress>
        virtual <address> incmail <emailaddress>
        virtual <address> mailfrom <emailaddress>
        defaultserver incmail <emailaddress>
        defaultserver mailfrom <emailaddress>

- Redhat added the -I option to disable RFC931 (AUTH/ident).  Added to
    the baseline so Redhat users don't see a loss of a feature.  Setting
    the timeout for rfc931 to zero will do the same thing in the ftpaccess
    file.

- The test for whether restricted-uid/restricted-gid applied should have
    been done before the chroot so it used the system /etc/passwd and
    /etc/group files.

- CDUP when you were already at the home directory, would complain about
    you being restricted (if you were).  Instead it should give a positive
    reply, and do nothing.  This makes it behave more like CDUP when you're
    not restricted to your home directory.

- deny-uid and deny-gid were being tested for anonymous users.  Bad move,
    it's too easy to forget to allow them.  Use 'defaultserver private' to
    keep anonymous users away.

- Correct the operation of the NLST command.  Finally.  mget should now
    work as users expect it to.

- Prevent buffer overruns when processing message files.

- Correct a reference through a NULL pointer when doing S/Key
    authentication and the user is not in the passwd file.

- Check the return code from select() when setting up a data connection.
    Under some rare conditions it is possible that the select was called
    for an fd_set which has no members, hanging the daemon.

- Ensure a pattern of "*" matches everything.  The new path_compare (used
    on upload and throughput clauses in the ftpaccess file) sets the option
    FNM_PATHNAME, so:

        *    matches everything
        /*   matches everything
        /*/* matches /dogs/toto and /dogs/toto/photos but not /dogs

- setproctitle() support added for UnixWare.

- Removed all FIXES files.  Merged their contents into this CHANGES file
    (the one you're reading now).  The old doc/FIXES directory has been
    tar'd and will be placed in the attic when 2.6.0 releases.

- Corrected an error in the MAPPING_CHDIR feature which could be used to
    gain root privileges on the server.

- Added -V command-line option to View the copyright and exit.

- Added the privatepw command and documentation.

- Port for FreeBSD corrected.

- Adding the LICENSE file to the baseline.

- Added print_copyright function so our copyright is embedded in the
    executables.

- WU-FTPD Development Group copyright headers added.  Original Copyright
    headers moved into the COPYRIGHT file.

- RCS Ids from 2.4.x removed and new templates added for wu-ftpd.org
    usage.

- Make sure the signal context is restored when jumping out of signal
    handlers.  This was causing signal 11 on some systems.

- Cleaned up the how-to of setting up virtual hosting support.

- Corrected header file dependencies.

- Changed NLST to nlst, necessary as ftpcmd.c #defines NLST.

- Tidied up virtual variables.

- Changed so compiles cleanly on SCO OpenServer 5, UnixWare 2 and
    UnixWare 7.

- Anonymous users could get in even though no class was defined for them.

- Support for non-ANSI/ISO compilers has been removed.  You MUST have and
    ANSI/ISO C compiler.  This has been true for some time, all that has
    changed is the (incomplete) support for older (K&R) compilers has been
    removed.

- Added Kent Landfield's NEWVIRT scheme for extensive virutal hosting.
    See the updated documentation on virtual hosting for details.

- ftprestart has been added to the base daemon kit.

- A buffer overrun in the ftpshut command has been corrected.  Since, on
    most sites, the ftpshut command is only usable by the superuser, this
    is not considered a security issue.  If you have installed ftpshut with
    suid-root permissions (not the default), then there is the possibility
    this overrun could be used to leverage root permissions.

- Several new ftpaccess clauses have been added.  These allow control of
    the various timeouts used within the daemon.  The new clauses are:

        timeout accept <seconds>
        timeout connect <seconds>
        timeout data <seconds>
        timeout idle <seconds>
        timeout maxidle <seconds>
        timeout RFC931 <seconds>

- Myriad places where inactivity timeouts were not being properly
    detected or handled have been corrected.

	The built-in directory listings, both the original NLST and the
	build-in LIST (ls), now detect inactivity.  The original NLST did
        not which could lead to hanging daemons.

	C FILE handles for data connections are now always flushed, then
        the socket is shutdown cleanly before being closed.

	As a side effect, the daemon now more often properly detects
	incomplete transfers.  This can lead, though, to the xferlog
	showing the correct byte count (meaning the daemon read or wrote
	that many bytes over the data connection), but still log the
	transfer as incomplete (meaning the socket did not properly
        shutdown so the client probably missed some data).

- The daemon no longer attempts to replace the system's <arpa/ftp.h>
    header when compiling.  Instead, it uses its own local copy at all
    times.

- The daemon will now wait for the transfer to complete before sending
    'Transfer complete' or similar messages.  This improves the daemon's
    reliability for poorly written clients which take recipt of the message
    as indication the transfer has completed rather than reading until the
    connection closes.

- Guest and anonymous logout was not recorded on Linux.  Removed call to
    updwtmp and returned to old method of updating the lastlog.

- Script "vr.sh" is no longer needed.  The Development Group will not be
    releasing patches to upgrade; they can be obtained from CVS if needed.

- "realpath_on_steroids" is no longer needed.  Removed.

- Use a custom version of fnmatch() which changes the rules for matching
    file and directory names.  The most visible result of this is
    noretrieve and allow-retrieve are now much more flexible.  See the
    ftpaccess manpage for examples.

- Use the correct SPT_TYPE for FreeBSD 2.0 or later.

- Correct the class= logic on the allow-retrieve clause.

- Enhanced DNS extensions.  This adds three ftpaccess clauses:

        dns refuse_mismatch <filename> [override]
        dns refuse_no_reverse <filename> [override]
        dns resolveroptions [options]

- Corrected a reference in the manpage for ftpconversions to ftpd.

- The string 'path-filter' is now used in the system logs to describe
    problems resulting from failing a path-filter check.  The daemon used
    to just say 'bad filename' which was misleading to some people.

- Added instruction on how to support PAM on Solaris.  Right now this
    means hand editing src/config/config.sol and
    src/makefiles/Makefile.sol.

- Checking that all platforms use config.h, src/config/config.isc was
    found to have forgotten to include the file.

- A security deficency on SunOS 4.1, not having a working getcwd()
    function, has been corrected by using the provided function.
    Compilation bugs in the portable getcwd() function have been corrected.

- The daemon will no longer hang attempting to close the RFC931 socket
    when the remote end is firewalled and does not respond to traffic for
    this protocol.  This was determined to be inappropriate handling of
    SIGALRM; handling for this signal has been cleaned up throughout the
    daemon.

- The daemon may now be built using GNU autoconf.  This is in the early
    stages and not all platforms may be supported.  The old build system
    will be maintained for at least the 2.6.0 release; until the major
    platforms are all known to be supported.

- Two new ftpaccess clauses have been added.  These allows the site admin
    to selectively allow PORT and PASV data connections where the remote IP
    address does not match the remote IP address on the control connection.
    The new clauses are:

        port-allow <class> [<addrglob> ...]
        pasv-allow <class> [<addrglob> ...]

- The daemon now includes an internal 'ls' command.

- Ported to Mac OS/X.

- Added (limited) support for AFS and DCE user authentication.  This is
    only know to work on AIX, and needs porting to other platforms.  For
    now, this requires hand work to enable.

- Added an ftpaccess clause to enable TCP keepalives.  This clause is:

        keepalive <yes|no>

- You can now specify the xferlog filename for the default server just as
    you can for the virtual hosts; in the ftpaccess file.  The new clause
    is:

        xferlog <absolute path>

- ftpaccess manpage cleaned up.  Many typos corrected, some techincal
    changes.  Indentation should now be correct.

- Apache's .indent.pro to the src and support directories.  Ran all *.c
    and *.h files through it.  ftpcmd.y has been indented by hand.  The
    code is now a lot more readable!

- A bug in the parsing for the deny !nameserved ftpaccess clause has been
    corrected.

- Technical corrections in the ftpd manpage.

- Add util/recompress.c as a more generic version of gzip2cmp.c

* Tue Sep 21 1999 Cristian Gafton <gafton@redhat.com>
- patch for allowing logins by users that do not have a local account on the
  machine, but are autheticated by PAM from a different database.

* Mon Sep 06 1999 Cristian Gafton <gafton@redhat.com>
- fix ident patch

* Tue Aug 31 1999 Michael K. Johnson <johnsonm@redhat.com>
- fixed roff subtlety

* Wed Aug 25 1999 <jbj@redhat.com>
- fix ftpd.c mapped_path buffer overflow.

* Mon Aug 23 1999 <jbj@redhat.com>
- apply fix for login bug (#1599).

* Sat Aug 21 1999 <jbj@redhat.com>
- include all quick-fixes from ftp.vr.net (#3482,#3866).

* Sat Jun 12 1999 <alan@redhat.com>
- Added the new -I option to toggle the use of ident

* Mon Jun  7 1999 <jbj@redhat.com>
- update to 2.5.0 (pathname patch no longer needed).
- use "/bin/ps -f -p #" to get correct ftpwho info (#2455).
- revert glob patch in order to fix "cd ~user" (#2798) and "ls foo*" (#2944).

* Mon Apr 19 1999 <ewt@redhat.com>
- fixed pathname overflow patch

* Sat Apr 17 1999 <ewt@redhat.com>
- use libc glob function
- patched up some overflows - ick.

* Fri Apr 16 1999 Cristian Gafton <gafton@redhat.com>
- version 2.4.2-vr17. Thank GOD! - important patches are already in. Joy an
  happyness will reign the world now.

* Sun Mar 21 1999 Cristian Gafton <gafton@redhat.com> 
- auto rebuild in the new build environment (release 6)

* Mon Feb 15 1999 Cristian Gafton <gafton@redhat.com>
- update to 2.4.2-beta18-vr14 from ftp.vr.net

* Mon Aug  3 1998 Jeff Johnson <jbj@redhat.com>
- fix busted symlinks.

* Thu Jul 16 1998 Jeff Johnson <jbj@redhat.com>
- update to 2.4.2-beta18

* Tue Jun 09 1998 Prospector System <bugs@redhat.com>
- translations modified for de

* Tue Jun  9 1998 Jeff Johnson <jbj@redhat.com>
- updated to 2.4.2-beta17 (fix problems #679/#680)

* Thu May 07 1998 Prospector System <bugs@redhat.com>
- translations modified for de, fr, tr

* Sun May 03 1998 Cristian Gafton <gafton@redhat.com>
- fixed the ps patch for the new ps convention (use ps www instead of ps -www)

* Sun Apr 12 1998 Cristian Gafton <gafton@redhat.com>
- added %clean section

* Sat Apr 11 1998 Cristian Gafton <gafton@redhat.com>
- updated to 2.4.2b16
- BuildRoot

* Fri Dec 12 1997 Cristian Gafton <gafton@redhat.com>
- added a patch to prevent a possible PORT command exploit
- cleaned up the .linux patch to get a clean compile on glibc

* Tue Oct 21 1997 Erik Troan <ewt@redhat.com>
- fixed copyright field

* Mon Oct 13 1997 Michael K. Johnson <johnsonm@redhat.com>
- Updated to new pam conventions.

* Mon Sep 22 1997 Erik Troan <ewt@redhat.com>
- Updated to beta 15, which fixes a number of security holes. Release 1
  if for RH 4.2, release 2 is glibc based.

* Mon Mar 03 1997 Michael K. Johnson <johnsonm@redhat.com>
- Moved from pam.conf to pam.d

* Mon Mar 03 1997 Erik Troan <ewt@redhat.com>
- xferstats should look for perl in /usr/bin, not /usr/local/bin
- provides the "ftpserver" virtual package

* Thu Feb 13 1997 Michael K. Johnson <johnsonm@redhat.com>
- Updated to beta-12, and created a new PAM patch from scratch, since
  the old one made massive changes to ftpd and caused some problems.

Summary: Tool for generating optimized packetfilter rules under GPL
Name: uif
Version: 1.02
Release: 1
License: GPL
Group: System
Source: http://lug.mfh-iserlohn.de/uif/uif-current.tar.bz2
URL: http://lug.mfh-iserlohn.de/uif/
Prereq: perl perl-netaddr-ip perl-ldap iptables
BuildRoot: %{_tmppath}/%{name}-%{version}-root

%description
UIF is used to generate optimized iptables(8) packetfilter rules, using a simple description file
specified by the user. Generated rules are provided in iptables-save(8) style.  uif can be used to read or write rulesets from or to LDAP servers in your network, which provides a global storing mechanism. (LDAP support is currently broken, note that you need to include the uif.schema to your slapd configuration in order to use it.)

%prep
%setup -q -n %{name}

%build

%install
rm -rf %{buildroot}
mkdir -p %{buildroot}

DESTDIR=%{buildroot} make install


%clean
rm -rf %{buildroot}
rm -rf %{_builddir}/%{buildsubdir}


%files
%defattr(-,root,root)
%defattr(0644,root,root,0755)
/etc/uif/services
/etc/default/uif
/etc/init.d/uif
/etc/ldap/schema/uif.schema
/usr/sbin/uif
/usr/share/man/man8/uif.8.gz
/usr/share/man/man5/uif.conf.5.gz
%doc docs/uif.conf.tmpl
%doc docs/examples.txt

%changelog
* Thu Jun 13 2002 Andreas Almstadt <almstadt@GONICUS.de>
 - first build

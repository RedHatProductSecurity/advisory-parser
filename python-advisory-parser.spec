%global pyname advisory-parser
%global summary Security flaw parser for upstream security advisories

# When building an RPM for RHEL (using a CentOS image), the dist tag
# default is 'el7.centos'. Override this to just 'el7' by looking at the
# %{rhel} macro (that is also defined on CentOS). It contains the major
# release version so append it to '.el'.
%if 0%{?rhel}
%define dist .el%{rhel}
%endif

Name:           python-%{pyname}
Version:        1.9
Release:        1%{?dist}
Summary:        %{summary}

Group:          Development/Libraries
License:        LGPL
URL:            https://pypi.org/project/advisory-parser/
Source0:        https://files.pythonhosted.org/packages/source/a/%{pyname}/%{pyname}-%{version}.tar.gz

BuildArch:      noarch

%if "%{?rhel}" == "8"
BuildRequires:  platform-python-devel
%else
BuildRequires:  python3-devel
%endif

%description
This library allows you to parse data from security advisories of certain
projects to extract information about security issues. The parsed
information includes metadata such as impact, CVSS score, summary,
description, and others.

%package -n python3-%{pyname}
Summary:        %{summary}
%{?python_provide:%python_provide python3-%{pyname}}
%if "%{?rhel}" == "7"
Requires:       python-beautifulsoup4 >= 4.0.0
%else
Requires:       python3-beautifulsoup4 >= 4.0.0
%endif

%description -n python3-%{pyname}
This library allows you to parse data from security advisories of certain
projects to extract information about security issues. The parsed
information includes metadata such as impact, CVSS score, summary,
description, and others.


%prep
%autosetup -n %{pyname}-%{version}

%build
%py3_build

%install
%py3_install

%files -n python3-%{pyname}
%license LICENSE
%doc README.rst COPYRIGHT
%{python3_sitelib}/*

%changelog
* Tue Dec 17 2019 Martin Prpic <mprpic AT redhat.com> 1.9-1
- release of version 1.9

* Thu Aug 15 2019 Martin Prpic <mprpic AT redhat.com> 1.8-1
- release of version 1.8

* Wed Apr 11 2018 Martin Prpic <mprpic AT redhat.com> 1.7-1
- release of version 1.7

* Wed Jan 17 2018 Martin Prpic <mprpic AT redhat.com> 1.6-1
- release of version 1.6

* Fri Nov 3 2017 Martin Prpic <mprpic AT redhat.com> 1.5-1
- release of version 1.5

* Fri Oct 24 2017 Viliam Krizan <vkrizan AT redhat.com> 1.4-1
- initial packaging

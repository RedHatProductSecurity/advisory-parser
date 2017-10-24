%global pyname advisory-parser
%global summary Security flaw parser for upstream security advisories
%if 0%{?fedora}
%global with_python3 1
%else
%global with_python3 0
%endif

# When building an RPM for RHEL (using a CentOS image), the dist tag
# default is 'el7.centos'. Override this to just 'el7' by looking at the
# %{rhel} macro (that is also defined on CentOS). It contains the major
# release version so append it to '.el'.
%if 0%{?rhel}
%define dist .el%{rhel}
%endif

Name:           python-%{pyname}
Version:        1.4
Release:        1%{?dist}
Summary:        %{summary}

Group:          Development/Libraries
License:        LGPL
URL:            https://pypi.org/project/advisory-parser/
Source0:        https://files.pythonhosted.org/packages/source/a/%{pyname}/%{pyname}-%{version}.tar.gz

BuildArch:      noarch

BuildRequires:  python-beautifulsoup4 >= 4.0.0
%if 0%{?fedora}
BuildRequires:  python2-devel
%else
# RHEL/CentOS (requires EPEL)
BuildRequires:  python-devel
BuildRequires:  python2-rpm-macros
%endif

BuildRequires:  pytest
BuildRequires:  python2-mock
%if 0%{?with_python3}
BuildRequires:  python3-devel
BuildRequires:  python3-pytest
BuildRequires:  python3-beautifulsoup4 >= 4.0.0
%endif

%description
This library allows you to parse data from security advisories of certain
projects to extract information about security issues. The parsed
information includes metadata such as impact, CVSS score, summary,
description, and others.

%package -n python2-%{pyname}
Summary:        %{summary}
%{?python_provide:%python_provide python2-%{pyname}}
Requires:       python-beautifulsoup4 >= 4.0.0

%description -n python2-%{pyname}
This library allows you to parse data from security advisories of certain
projects to extract information about security issues. The parsed
information includes metadata such as impact, CVSS score, summary,
description, and others.


%if 0%{?with_python3}
%package -n python3-%{pyname}
Summary:        %{summary}
%{?python_provide:%python_provide python3-%{pyname}}
Requires:       python3-beautifulsoup4 >= 4.0.0

%description -n python3-%{pyname}
This library allows you to parse data from security advisories of certain
projects to extract information about security issues. The parsed
information includes metadata such as impact, CVSS score, summary,
description, and others.
%endif


%prep
%autosetup -n %{pyname}-%{version}

%build
%py2_build
%if 0%{?with_python3}
%py3_build
%endif

%install
%py2_install
%if 0%{?with_python3}
%py3_install
%endif

%check
%{__python2} -m pytest tests
%if 0%{?with_python3}
%{__python3} -m pytest tests
%endif

%files -n python2-%{pyname}
%license LICENSE
%doc README.rst COPYRIGHT
%{python2_sitelib}/*

%if 0%{?with_python3}
%files -n python3-%{pyname}
%license LICENSE
%doc README.rst COPYRIGHT
%{python3_sitelib}/*
%endif

%changelog
* Thu Oct 24 2017 Viliam Krizan <vkrizan AT redhat.com> 1.4-1
- initial packaging


#!/usr/bin/env bash

target_os=$1
spec_file=$2

if [ -z "$spec_file" ]; then
    echo 'ERROR: spec file not specified.'
    exit 1
fi

prep_env() {
    # Prepare environment
    mkdir -p ./{RPMS,SRPMS}
    mkdir -p ~/rpmbuild/{SPECS,SOURCES,SRPMS,RPMS}

    # Copy created source archive to sources
    cp dist/* ~/rpmbuild/SOURCES
}

deps_fedora() {
    # Install RPM building dependencies; skips Recommends or Supplements ("weak dep") packages
    dnf install --setopt install_weak_deps=false -y rpm-build rpmlint dnf-plugins-core

    prep_env

    # Install missing dependencies for building an RPM package; skips Recommends or Supplements
    # ("weak dep") packages
    dnf builddep --setopt install_weak_deps=false -y --spec "$spec_file"
}

deps_el7() {
    # Install Python 3 and RPM-building dependencies
    yum install -y python3 rpm-build rpmlint python-rpm-macros

    prep_env

    # Install missing dependencies for building our RPM package
    yum-builddep -y "$spec_file"
}

deps_el8() {
    # Install Python 3, RPM-building dependencies, and builddep DNF plug-in; skips Recommends or
    # Supplements ("weak dep") packages. glibc-langpack-en is installed as a workaround for BZ#1668400.
    dnf install --setopt install_weak_deps=false -y python3 rpm-build rpmlint dnf-plugins-core glibc-langpack-en

    prep_env

    # Install missing dependencies for building our RPM package; skips Recommends or Supplements
    # ("weak dep") packages
    dnf builddep --setopt install_weak_deps=false -y --spec "$spec_file"
}

case "$target_os" in
    fedora)
        deps_fedora
        ;;
    el7)
        deps_el7
        ;;
    el8)
        deps_el8
        ;;
    *)
        echo "ERROR: unknown target OS specified."
        exit 1
        ;;
esac

# Build source and binary packages from spec file
rpmbuild -ba "$spec_file"

# Move to standard locations
mv ~/rpmbuild/RPMS/* ./RPMS
mv ~/rpmbuild/SRPMS/* ./SRPMS

# Lint created RPMs
rpmlint $(find ./RPMS -name *.rpm)

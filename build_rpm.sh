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
    # Install RPM building dependencies; skips Recommends or Supplements
    # ("weak dep") packages
    dnf install --setopt install_weak_deps=false -y rpm-build rpmlint dnf-plugins-core findutils

    prep_env

    # Install missing dependencies for building an RPM package; skips
    # Recommends or Supplements ("weak dep") packages
    dnf builddep --setopt install_weak_deps=false -y --spec "$spec_file"
}

deps_el7() {
    # Install EPEL (for python-rpm-macros)
    yum install -y https://dl.fedoraproject.org/pub/epel/epel-release-latest-7.noarch.rpm

    # Install RPM building dependencies
    yum install -y rpm-build rpmlint findutils python-rpm-macros

    prep_env

    # Install missing dependencies for building an RPM package
    yum-builddep -y "$spec_file"
}

case "$target_os" in
    fedora)
        deps_fedora
        ;;
    el7)
        deps_el7
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

# vim:ft=spec

%define file_prefix M4_FILE_PREFIX
%define file_ext M4_FILE_EXT

%define file_version M4_FILE_VERSION
%define file_release_tag %{nil}M4_FILE_RELEASE_TAG
%define file_release_number M4_FILE_RELEASE_NUMBER
%define file_build_number M4_FILE_BUILD_NUMBER
%define file_commit_ref M4_FILE_COMMIT_REF

Name:           python3-dpres-signature
Version:        %{file_version}
Release:        %{file_release_number}%{file_release_tag}.%{file_build_number}.git%{file_commit_ref}%{?dist}
Summary:        Tools for creating and validating SMIME signatures.
Group:          System Environment/Library
License:        LGPL3+
URL:            https://www.digitalpreservation.fi
Source0:        %{file_prefix}-v%{file_version}%{?file_release_tag}-%{file_build_number}-g%{file_commit_ref}.%{file_ext}
BuildRoot:      %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)
BuildArch:      noarch

Requires:       python36-m2crypto python36-six
BuildRequires:	python36-pytest python3-setuptools

%description
Tools for creating and validating SMIME signatures.

%prep
find %{_sourcedir}
%setup -n %{file_prefix}-v%{file_version}%{?file_release_tag}-%{file_build_number}-g%{file_commit_ref}

%build
# do nothing

%install
make install3 PREFIX="%{_prefix}" ROOT="%{buildroot}"

# Rename executables to prevent naming collision with Python 2 RPM
sed -i 's/\/bin\/sign-file$/\/bin\/sign-file-3/g' INSTALLED_FILES
sed -i 's/\/bin\/verify-signed-file$/\/bin\/verify-signed-file-3/g' INSTALLED_FILES
mv %{buildroot}%{_bindir}/sign-file %{buildroot}%{_bindir}/sign-file-3
mv %{buildroot}%{_bindir}/verify-signed-file %{buildroot}%{_bindir}/verify-signed-file-3

echo "-- INSTALLED_FILES"
cat INSTALLED_FILES
echo "--"

%post

%postun

%clean

%files -f INSTALLED_FILES
%defattr(-,root,root,-)


# TODO: For now changelot must be last, because it is generated automatically
# from git log command. Appending should be fixed to happen only after %changelog macro
%changelog


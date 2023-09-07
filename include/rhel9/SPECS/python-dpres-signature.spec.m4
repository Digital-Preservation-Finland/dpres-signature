# vim:ft=spec

%define file_prefix M4_FILE_PREFIX
%define file_ext M4_FILE_EXT

%define file_version M4_FILE_VERSION
%define file_release_tag %{nil}M4_FILE_RELEASE_TAG
%define file_release_number M4_FILE_RELEASE_NUMBER
%define file_build_number M4_FILE_BUILD_NUMBER
%define file_commit_ref M4_FILE_COMMIT_REF

Name:           python-dpres-signature
Version:        %{file_version}
Release:        %{file_release_number}%{file_release_tag}.%{file_build_number}.git%{file_commit_ref}%{?dist}
Summary:        Tools for creating and validating SMIME signatures.
Group:          System Environment/Library
License:        LGPLv3+
URL:            https://www.digitalpreservation.fi
Source0:        %{file_prefix}-v%{file_version}%{?file_release_tag}-%{file_build_number}-g%{file_commit_ref}.%{file_ext}
BuildRoot:      %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)
BuildArch:      noarch

BuildRequires: python3-devel
BuildRequires: pyproject-rpm-macros
BuildRequires: %{py3_dist pip}
BuildRequires: %{py3_dist setuptools}
BuildRequires: %{py3_dist wheel}

%global _description %{expand:
Tools for creating and validating SMIME signatures.}

%description %_description

%package -n python3-dpres-signature
Summary: %{summary}

%description -n python3-dpres-signature %_description

%prep
%autosetup -n %{file_prefix}-v%{file_version}%{?file_release_tag}-%{file_build_number}-g%{file_commit_ref}

%build
%pyproject_wheel

%install
%pyproject_install
%pyproject_save_files dpres_signature

# TODO: executables with "-3" suffix are added to maintain compatibility with our systems.
# executables with "-3" suffix should be deprecated.
cp %{buildroot}%{_bindir}/sign-file %{buildroot}%{_bindir}/sign-file-3
cp %{buildroot}%{_bindir}/verify-signed-file %{buildroot}%{_bindir}/verify-signed-file-3

%files -n python3-dpres-signature -f %{pyproject_files}
%license LICENSE
%doc README.rst
%{_bindir}/sign-file
%{_bindir}/sign-file-3
%{_bindir}/verify-signed-file
%{_bindir}/verify-signed-file-3

# TODO: For now changelog must be last, because it is generated automatically
# from git log command. Appending should be fixed to happen only after %changelog macro
%changelog

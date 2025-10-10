
# Script auto install SIEM Ansible
```#!/bin/sh
# TODO.md

if [ "$1" = "-v" ]; then
  ANSIBLE_VERSION="${2}"
fi

wait_for_cloud_init() {
  while pgrep -f "/usr/bin/python /usr/bin/cloud-init" >/dev/null 2>&1; do
    echo "Waiting for cloud-init to complete"
    sleep 1
  done
}

dpkg_check_lock() {
  while fuser /var/lib/dpkg/lock >/dev/null 2>&1; do
    echo "Waiting for dpkg lock release"
    sleep 1
  done
}

apt_install() {
  dpkg_check_lock && DEBIAN_FRONTEND=noninteractive apt-get install -y \
    -o DPkg::Options::=--force-confold -o DPkg::Options::=--force-confdef "$@"
}

if [ "x$KITCHEN_LOG" = "xDEBUG" ] || [ "x$OMNIBUS_ANSIBLE_LOG" = "xDEBUG" ]; then
  export PS4='(${BASH_SOURCE}:${LINENO}): - [${SHLVL},${BASH_SUBSHELL},$?] $ '
  set -x
fi

if ! command -v ansible-playbook >/dev/null 2>&1; then
  if [ -f /etc/debian_version ] || grep -qi ubuntu /etc/os-release; then
    wait_for_cloud_init
    dpkg_check_lock && apt-get update -q

    apt_install python3-pip python3-yaml python3-jinja2 python3-httplib2 python3-netaddr python3-paramiko python3-pkg-resources libffi-dev python3-all-dev python3-mysqldb python3-selinux python3-boto sshpass build-essential bzip2 file findutils git gzip mercurial procps subversion sudo tar debianutils unzip xz-utils zip

    # Install python-keyczar from apt or pip fallback
    if ! dpkg_check_lock || ! apt-cache search python-keyczar | grep -q python-keyczar; then
      pip3 install python-keyczar
    else
      apt_install python-keyczar
    fi

    # Install extra python libs for encryption and AWS SDKs
    pip3 install cryptography pyrax pysphere boto passlib dnspython pyopenssl

    mkdir -p /etc/ansible/
    printf "%s\n" "[local]" "localhost" > /etc/ansible/hosts

    if [ -z "$ANSIBLE_VERSION" ]; then
      pip3 install -q ansible
    else
      pip3 install -q "ansible==$ANSIBLE_VERSION"
    fi

  else
    echo 'ERROR: Unsupported or undetected Linux distribution.'
    exit 1
  fi
fi
```






#!/usr/bin/env bash

set -x

user="$1"
sshdir="$2/.ssh"

function main {
  if check_file "$sshdir/akds"; then
    fetch_akds $sshdir/akds
    exit 0
  fi
  
  if check_file "$sshdir/akd"; then
    fetch_akd $sshdir/akd
    exit 0
  fi
  
  if check_file "$sshdir/url"; then
    fetch_url $sshdir/url
    exit 0
  fi

  echo "No relevant files found in user's .ssh"
  exit 0
}

function check_file {
  if [ -f $1 ]; then
    check_ownership $user $1
  else
    return 1
  fi
}

function check_ownership {
  local owner=$(stat -c %U $2)
  local perms=$(stat -c %A $2 | cut -c6,9)

  if [ $owner != $1 ]; then
    return 1
  elif [ $perms != "--" ]; then
    return 1
  fi

  return 0
}

main "$@"; exit
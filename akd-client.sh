#!/usr/bin/env bash

set -x

user="$1"
sshdir="$2/.ssh"

function main {
  if check_file "$sshdir/akds"; then
    fetch_akds "$sshdir/akds"
    exit 0
  fi
  
  if check_file "$sshdir/akd"; then
    fetch_akd "$sshdir/akd"
    exit 0
  fi
  
  if check_file "$sshdir/url"; then
    fetch_url "$sshdir/url"
    exit 0
  fi

  echo "No relevant files found in user's .ssh"
  exit 0
}


function check_file {
  if [ -f "$1" ]; then
    check_ownership "$user" "$1"
  else
    return 1
  fi
}

function check_ownership {
  local owner=$(stat -c %U "$2")
  local perms=$(stat -c %A "$2" | cut -c6,9)

  if [ "$owner" != "$1" ]; then
    return 1
  elif [ "$perms" != "--" ]; then
    return 1
  fi

  return 0
}


function fetch_akds {
  local akds=$(<"$1")
  local akds_record=$(dig -t txt +short "$akds")

  parse_akds "$akds_record"
}

function parse_akds {
  local regex_1="\"v=akds; s=([^\"]+)\""
  [[ "$*" =~ $regex_1 ]]

  local akd_record=$(base64 -d "${BASH_REMATCH[1]}" | gpg -qd - 2>/dev/null)

  parse_akd "$akd_record"
}


function fetch_akd {
  local akd=$(<"$1")
  local akd_record=$(dig -t txt +short "$akd")
  
  parse_akd "$akd_record"
}

function parse_akd {
  local regex_1="\"v=akd; ([^\"]+)\""
  local regex_2="^k=(.+)"
  local separator="; k="

  [[ $* =~ $regex_1 ]]
  [[ ${BASH_REMATCH[1]} =~ $regex_2 ]]

  printf '%s\n' "${BASH_REMATCH[1]//$separator/$'\n'}"
}


function fetch_url {
  local url=$(<"$1")
  curl -s "$url"
}

main "$@"; exit
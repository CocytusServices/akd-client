#!/usr/bin/env bash

query_user="$1"
dot_ssh="$2/.ssh"


if [ -f "$dot_ssh/akds" ]; then
  check_ownership $query_user "$dot_ssh/akds"
  fetch_akds < $dot_ssh/akds
  exit 0

elif [ -f "$dot_ssh/akd" ]; then
  check_ownership $query_user "$dot_ssh/akd"
  fetch_akd < $dot_ssh/akd
  exit 0

elif [ -f "$dot_ssh/url" ]; then
  check_ownership $query_user "$dot_ssh/url"
  fetch_url < $dot_ssh/url
  exit 0

else
  echo "No relevant files found in user's .ssh"
  exit 0

fi



check_ownership () {
  local owner=$(stat -c %U $2)
  local perms=$(stat -c %A $2)
  
  if [ $owner != $1 ]; then
    return 1
  elif [ $perms | cut -c6,9 != "--" ]
    return 1
  fi
}
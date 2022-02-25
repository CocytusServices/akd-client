# AKD Client
This is an `AuthorizedKeysCommand`-compatible client for controlling SSH access via AKD or AKDS records stored in DNS.  
  
  
## Setup
1. Download `akd-client.sh` and place it in `/etc/ssh`
2. Make sure its owned by root, and is `go-wx`
3. Add the following line to `/etc/ssh/sshd_config`:  
`AuthorizedKeysCommand /bin/bash /etc/ssh/akd-client.sh %h`
4. Create the corresponding file in each user's `.ssh/` folder
  

## Configuration
There are 3 types of endpoints AKD Client can fetch from:
1. AKD
- A DNS record which contains public   
`~/.ssh/akd:`  
`_akd.cocytus.services`  

2. AKDS
- AKD, but with an attached GPG signature  
`~/.ssh/akds:`  
`_akd.cocytus.services;GPGKEY`  
3. URL
- A plain ol' URL pointing to an `authorized_keys`-style file  
`~/.ssh/url:`  
`https://github.com/NotActuallyTerry.keys`  
  

## AKD Format

AKD is stored in a DNS record in the following form:  
`v=akd; k=ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPXESKtyAsXISE76L65F78IB8dbTLUBB2wRhFJclzHd1 contact@ike.id.au; k=ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINP7VeeBHLWFJtAOdbEriYml5rl08szuthQii1GBcBtr terry@ceilingfan.ike.id.au;`  

The record MUST start with `v=akd;` and MUST contain ONE OR MORE pubkeys starting with `k=`, with each entry ending in a semicolon.
  

## AKDS Format

AKDS is stored in a DNS record in the following form:  
`k=akds; s=owGbwMvMwCEmmR69+cfzyGuMpw8oJTEkSSSvK7NNzE6xVsi2LS7O0E1NMTI1NbRUcAQCZ2O/qkRn
w5woF09DvxBXU5CYZ0CEa7B3SaVjcYRnsKu5mY+ZqZu5haeTRUpSiE+ok5NReVCGm1dyTpVHiqFC
cn5eSWJyiUNmdqpeZopeYinRtvgFmIelpjp5+IS7eZU4+qckuRZlRubmmBblGFgUV5WWZARmZhq6
OyU7lRQplKQWFVU6JKdm5mTmpacl5ukhrOPqKGVhEONgkBVTZNnm6dj36MJqG4feP32wQGBlAgbA
RgYuTgGYCJMNI0OD5d02D1eNslfOsZIO9xmFGzx74qPnnkuxk5065VjJRAmGfwZK+vneqa4VHfff
Cjw5d9Rrp/PmZzwTTE4oOimcfrtyBh8A`  

The record MUST start with `v=akds;` and MUST contain ONE signature entry.  
The signature entry (`s=`) is created by making an AKD record as above, signing it using GPG, and base64 encoding it. This can be achieved by piping the record into the STDIN of `gpg -s | base64`
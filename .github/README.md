# AKD Client
This is an `AuthorizedKeysCommand`-compatible client for controlling SSH access via AKD (**a**uthorized_**k**eys **d**istribution) or AKDS (**a**uthorized_**k**eys **d**istribution, **s**igned) records stored in DNS.

## Setup
1. Download `akd-client` and install it wherever it can be accessed by root (`/usr/local/bin/` works fine)
2. Make sure its owned by root, and is `go-wx`
3. Add the following line to `/etc/ssh/sshd_config`:  
`AuthorizedKeysCommand /path/to/akd-client -c %h/.ssh/akd.toml`
4. Create the corresponding config file in each user's `.ssh/` folder
5. Restart `sshd`

If you're feeling brave, rename your `authorized_keys` file and try SSH in. If all goes well, you should be let through. If not, try running `akd-client` manually and check the output.

## Configuration
### DNS
AKD/S operates using TXT records with either `v=akd;` or `v=akds;` headers. These help differentiate from other TXT-based protocols as well as determine whether the data is cryptographically signed.

The key format is as follows:  
- AKD: `v=akd; k=<base64-encoded authorized_keys...>;`  
- AKDS: `v=akds; k=<base64-encoded authorized_keys...>; s=<base64-encoded PGP signature...>;`  

The order of the `k=` and `s=` sections in the AKDS record is arbitrary. Each keypair in the record must start with its identifier (e.g. `k`), followed by `=` and the value, ending with `;`.

The `authorized_keys` data is only encoded in Base64, so it can easily be pulled out with a DNS request and decoded manually if needed.

Here is an example record value using AKDS:
```
v=akds; s=iHUEABYKAB0WIQQ3uvv2LpbDyGv3Lm7MdkksvhHnFQUCYjxAQwAKCRDMdkksvhHnFUZiAQC2BM76AzoprX+KEcrJWyr6e5wODi3wbvLLUzBh7PnX8gEA0caQEWB890KlufnEaWy84WvVXNR1O8iIbWGFEFLMzQ8=; k=c3NoLWVkMjU1MTkgQUFBQUMzTnphQzFsWkRJMU5URTVBQUFBSUY1dld0eE54S2FFUllZUjNaMzRhV1JSYlZPQm5Hd3ZTMUgrd0VsdXpNalogdG9tQGljZTUudGVtLnBhcnR5CnNzaC1lZDI1NTE5IEFBQUFDM056YUMxbFpESTFOVEU1QUFBQUlJVGJDdmpTOGFtN00rb3JBbmdLYTlKTGV0U29mS2ZuVmpOVm5lL1QvRWROIHRvbUB3aW4uaWNlNS50ZW0ucGFydHkKc3NoLWVkMjU1MTkgQUFBQUMzTnphQzFsWkRJMU5URTVBQUFBSUJHdkw1RVJEZ2ZKQmhydEZUOTkzNFpCcEZjRGI2andaOGQ0YnVPT2JVL2QgdG9tQHV0aWxpYm9vay50ZW0ucGFydHkKc3NoLWVkMjU1MTkgQUFBQUMzTnphQzFsWkRJMU5URTVBQUFBSUlLQlh6MkNwclVwWVJOOSt5VW9sc3NiMC9naU0zc2NRMkY0UVVZaXRyVnkgdG9tQG1hY2Jvb2sudGVtLnBhcnR5CnNzaC1lZDI1NTE5IEFBQUFDM056YUMxbFpESTFOVEU1QUFBQUlCdXZSc29GNHhpL2NQcEd5RE4yUkt6NzlNOE02NklvYytyS0RaVFc3dnJLIHRvbUBlZGdlMjAudGVtLnBhcnR5;
```

The signature entry (`s=`) is created by making an AKD record as above, signing it using GPG, and base64 encoding it. This can be achieved by piping the record into the STDIN of `gpg -s | base64`.

### `akd-client`
The client needs to be configured with the record it will be checking and (optionally if using AKDS) the public key to verify the AKDS record against. By default `akd-client` will try read this in from `./config.toml`, but you can change this by specifying a path with the `-c` argument.

See [config.toml](/config.toml) for a template.

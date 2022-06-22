package main

import (
    "fmt"
    "os"
    "io"
    "net"
    "regexp"
    "strings"
    "flag"
    "errors"
    "bufio"
    "syscall"
    "net/http"
    "path/filepath"
    "encoding/base64"
    "golang.org/x/crypto/ssh"
    "github.com/BurntSushi/toml"
    "github.com/ProtonMail/gopenpgp/v2/crypto"
)

// Config file format
type Config struct {
    RecordName              string
    PubkeyStr               string `toml:"Pubkey"`
    pubkey                  *crypto.Key
    Url                     string
    AllowUrlFallback        bool
    AcceptUnverified        bool
    OverwriteAuthorizedKeys bool
    AuthorizedKeysPath      string
}

type CliArgs struct {
    ConfigPath string
}

// Some patterns for the AKD/S record format
var header_pattern = regexp.MustCompile("v=(akds?);")
var key_pattern = regexp.MustCompile("k=([A-Za-z0-9+/=]+);")
var sig_pattern = regexp.MustCompile("s=([A-Za-z0-9+/=]+);")

func parseArgs() CliArgs {
    var args CliArgs

    // Build args and parse them
    flag.StringVar(&args.ConfigPath, "c", "", "Path to config file (default: config.toml)")
    flag.Parse()

    // Set defaults
    if args.ConfigPath == "" {
        args.ConfigPath = "config.toml"
    }

    return args
}

// Loads config in from the given path
func loadConfig(path string) (Config, error) {
    var config Config

    // Try read in from the given path
    _, err := toml.DecodeFile(path, &config)
    if err != nil {
        return config, err
    }

    // Ensure we've been given either a record name or URL
    if config.RecordName == "" && config.Url == "" {
        return config, errors.New("No value for RecordName or Url provided, cannot retrieve any keys")
    }

    // Parse the pubkey if we've been given one
    if config.RecordName != "" && config.PubkeyStr != "" {
        key, err := crypto.NewKeyFromArmored(config.PubkeyStr)
        if err != nil {
            return config, errors.New("Failed to parse key from config file")
        } else {
            config.pubkey = key
        }
    }

    // Ensure we have an authorized_keys path if we want to write to it
    if config.OverwriteAuthorizedKeys && config.AuthorizedKeysPath == "" {
        return config, errors.New("Missing authorizedKeysPath when overwriteAuthorizedKeys = true")
    }

    return config, nil
}

func parseAKDRecord(record string) (string, string, string, error) {
    var record_type, key_blob, sig_blob string

    header := header_pattern.FindStringSubmatch(record)
    if len(header) > 1 {
        record_type = header[1]
        key_match := key_pattern.FindStringSubmatch(record)
        sig_match := sig_pattern.FindStringSubmatch(record)

        // Try parse the two blobs (if present)
        if len(sig_match) > 1 {
            sig_blob = sig_match[1]
        }
        if len(key_match) > 1 {
            key_blob = key_match[1]
        }

        // Ensure AKDS record has a signature blob
        if record_type == "akds" && sig_blob == "" {
            return "", "", "", errors.New("Failed to extract signature from AKDS record")
        }

        // Ensure there is a key blob
        if key_blob == "" {
            return "", "", "", errors.New("Failed to extract a key blob from " + strings.ToUpper(record_type) + " record")
        }
    } else {
        return "", "", "", errors.New("Not a suitable AKD/S record")
    }
    
    return record_type, key_blob, sig_blob, nil
}

func verifySignature(data []byte, sig []byte, pubkey *crypto.Key) (bool, error) {
    // Check for missing/empty signature
    if len(sig) == 0 {
        return false, errors.New("Failed to verify signature: AKDS record has empty or missing signature")
    } else {
        // Ensure we have a pubkey to verify with
        if pubkey == nil {
            return false, errors.New("No pubkey specified, cannot verify AKDS record")
        }

        // Parse our keys and signature as PGP data
        pgpMessage := crypto.NewPlainMessage(data)
        pgpSignature := crypto.NewPGPSignature(sig)
        pgpKeyring, err := crypto.NewKeyRing(pubkey)
        if err != nil {
            return false, errors.New("Failed to parse key or signature as valid PGP data")
        }

        // Verify the signature
        err = pgpKeyring.VerifyDetached(pgpMessage, pgpSignature, crypto.GetUnixTime())
        return err == nil, nil
    }
}

func validateAuthorizedKeys(keys string) (bool, error) {
    scanner := bufio.NewScanner(strings.NewReader(keys))
    for scanner.Scan() {
        _, _, _, _, err := ssh.ParseAuthorizedKey(scanner.Bytes())
        if err != nil {
            return false, err
        }
    }

    return true, scanner.Err()
}

// Gets authorised keys from an AKD/S record in DNS.
// Returns the key list, whether it was verified with PGP, and any error encountered
func getAKDKeys(record_name string, pubkey *crypto.Key, accept_unverified bool) (string, bool, error) {
    // Retrieve AKD/S records
    records, _ := net.LookupTXT(record_name)

    var record_type, key_blob, sig_blob string
    for _, record := range records {
        fmt.Fprintln(os.Stderr, "Record: " + record)

        // Try parse the record out into its constituent blobs
        var err error
        record_type, key_blob, sig_blob, err = parseAKDRecord(record)
        if err != nil {
            fmt.Fprintln(os.Stderr, "Failed to parse record: " + err.Error())
            continue
        }

        // Stop iterating once we've found an eligible record
        break
    }

    // Make sure a record was chosen
    if record_type == "" {
        return "", false, errors.New("No suitable AKD/S record found")
    } else if record_type == "akd" && !accept_unverified {
        return "", false, errors.New("Found AKD record but not accepting unverified records")
    }

    // Attempt to decode the key blob from base64
    key, err := base64.StdEncoding.DecodeString(key_blob)
    if err != nil {
        return "", false, errors.New("Failed to decode key blob: " + err.Error())
    }

    var sig []byte
    if record_type == "akds" {
        // Attempt to decode the signature blob
        sig, err = base64.StdEncoding.DecodeString(sig_blob)
        if err != nil {
            if !accept_unverified {
                return "", false, errors.New("Failed to decode signature: " + err.Error())
            } else {
                fmt.Fprintln(os.Stderr, "Failed to decode signature:  " + err.Error())
            }
        }

        // Perform signature verification if we have a signature to verify
        verified, err := verifySignature(key, sig, pubkey)
        if err != nil && !accept_unverified {
            return "", false, errors.New("Failed to verify AKDS signature: " + err.Error())
        }

        return string(key), (verified && err == nil), nil
    } else {
        return string(key), false, nil
    }
}

// Gets authorised keys from the given URL.
// Returns the key list and any error encountered
func getUrlKeys(url string) (string, error) {
    response, err := http.Get(url)
    if err != nil {
        return "", errors.New("Error when requesting URL: " + err.Error())
    }

    if response.StatusCode >= 400 {
        return "", errors.New("Unsuccessful response code when requesting URL: " + response.Status)
    }

    defer response.Body.Close()
    body, err := io.ReadAll(response.Body)
    if err != nil {
        return "", errors.New("Failed to read response body: " + err.Error())
    }

    return string(body), nil
}

func main() {
    // Parse CLI args
    args := parseArgs()

    // Load in config
    config, err := loadConfig(args.ConfigPath)
    if err != nil {
        fmt.Fprintln(os.Stderr, "Failed to load config from " + args.ConfigPath + ": " + err.Error())
        return
    }

    // Prioritise AKD if possible
    var keys string
    if config.RecordName != "" {
        var verified bool
        keys, verified, err = getAKDKeys(config.RecordName, config.pubkey, config.AcceptUnverified)
        if err != nil {
            // Print out the error but don't return yet, we'll give the URL a try
            fmt.Fprintln(os.Stderr, "Failed to get keys from AKD/S record: " + err.Error())

            // Stop here if URL fallback is possible but not allowed
            if config.Url != "" && !config.AllowUrlFallback {
                fmt.Fprintln(os.Stderr, "URL specified but fallback not allowed")
                return
            }
        } else  {
            if verified {
                fmt.Fprintln(os.Stderr, "Successfully verified AKDS data")
            } else {
                fmt.Fprintln(os.Stderr, "Accepting unverified AKDS data")
            }
        }
    }

    // Use URL if AKD not available
    if config.RecordName == "" || (err != nil && config.Url != "") {
        keys, err = getUrlKeys(config.Url)
        if err != nil {
            fmt.Fprintln(os.Stderr, "Failed to get keys from URL: " + err.Error())
            return
        }
    } else if err != nil && config.Url == "" {
        fmt.Fprintln(os.Stderr, "Failed to get any keys: " + err.Error())
        return
    }

    // Validate the key blob to ensure it conforms with the OpenSSH authorized_keys format
    var valid bool
    valid, err = validateAuthorizedKeys(keys)
    if err != nil || !valid {
        fmt.Fprintln(os.Stderr, "Failed to validate key blob format")
        return
    }

    // Print out for OpenSSH to handle
    fmt.Print(keys)

    // Try writing out to authorized_keys, if enabled
    if config.OverwriteAuthorizedKeys {
        var err error
        var path string
        if filepath.IsAbs(config.AuthorizedKeysPath) {
            // Absolute
            path = config.AuthorizedKeysPath
        } else {
            // Relative
            path = filepath.Join(filepath.Dir(args.ConfigPath), config.AuthorizedKeysPath)
        }

        // Create or truncate the file
        file, err := os.Create(path)
        if err != nil {
            fmt.Fprintln(os.Stderr, "Failed to create authorized_keys file at "+path)
            return
        }

        // Write out the keys
        _, err = file.Write([]byte(keys))
        if err != nil {
            fmt.Fprintln(os.Stderr, "Failed to write authorized_keys file to "+path)
            return
        }

        // Change the file permissions to 600
        err = file.Chmod(0600)
        if err != nil {
            fmt.Fprintln(os.Stderr, "Failed to change file permissions on "+path)
            // Failed permissions, but keep going to try ownership
        }

        // Mirror ownership of parent dir
        parentDir := filepath.Dir(path)
        var parentDirInfo os.FileInfo
        parentDirInfo, err = os.Stat(parentDir)
        if err != nil {
            fmt.Fprintln(os.Stderr, "Failed to stat "+parentDir)
            return
        }
        parentDirStat := parentDirInfo.Sys().(*syscall.Stat_t)
        if err != nil {
            fmt.Fprintln(os.Stderr, "Failed to get syscall stat for "+parentDir)
            return
        }
        err = file.Chown(int(parentDirStat.Uid), int(parentDirStat.Gid))
        if err != nil {
            fmt.Fprintf(os.Stderr, "Failed to set file ownership on %s to %d:%d: %v\n", path, parentDirStat.Uid, parentDirStat.Gid, err)
        }

        // Clean up
        file.Close()
    }
}

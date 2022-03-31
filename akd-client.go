package main

import (
    "fmt"
    "os"
    "net"
    "regexp"
    "strings"
    "flag"
    "errors"
    "bufio"
    "encoding/base64"
    "github.com/BurntSushi/toml"
    "github.com/ProtonMail/gopenpgp/v2/crypto"
)

// Config file format
type Config struct {
    RecordName string
    PubkeyStr string `toml:"Pubkey"`
    pubkey *crypto.Key
    AcceptUnverified bool
}

type CliArgs struct {
    ConfigPath string
}

// Some patterns for the AKD/S record format
var header_pattern = regexp.MustCompile("v=(akds?);")
var key_pattern = regexp.MustCompile("k=([A-Za-z0-9+/=]+);")
var sig_pattern = regexp.MustCompile("s=([A-Za-z0-9+/=]+);")
var authorized_keys_pattern = regexp.MustCompile("^(?:#.*|(?:(?:(?:no-)?(?:(?:agent|port|X11)-forwarding|pty|user-rc)|cert-authority|(?:no-touch|verify)-required|restrict|(?:command|environment|expiry-time|from|permit(?:listen|open)|principals|tunnel)=\".+\")(?:,(?:(?:no-)?(?:(?:agent|port|X11)-forwarding|pty|user-rc)|cert-authority|(?:no-touch|verify)-required|restrict|(?:command|environment|expiry-time|from|permit(?:listen|open)|principals|tunnel)=\".+\"))* )?(?:sk-(?:ecdsa-sha2-nistp256|ssh-ed25519)@openssh\\.com|ecdsa-sha2-nistp(?:256|384|521)|ssh-(?:ed25519|dss|rsa)) .+(?: .*)?)?$")

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

    // Parse the pubkey if we've been given one
    if config.PubkeyStr != "" {
        key, err := crypto.NewKeyFromArmored(config.PubkeyStr)
        if err != nil {
            return config, errors.New("Failed to parse key from config file")
        } else {
            config.pubkey = key
        }
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
        if !authorized_keys_pattern.MatchString(scanner.Text()) {
            return false, nil
        }
    }

    return true, scanner.Err()
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

    // Retrieve AKD/S records
    records, _ := net.LookupTXT(config.RecordName)

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
        fmt.Fprintln(os.Stderr, "No suitable AKD/S record found")
        return
    }

    fmt.Fprintln(os.Stderr, "Record type: " + record_type)
    fmt.Fprint(os.Stderr, "Has keys? ")
    if len(key_blob) > 0 {
        fmt.Fprintln(os.Stderr, "Yes")
    } else {
        fmt.Fprintln(os.Stderr, "No")
    }
    fmt.Fprint(os.Stderr, "Has signature? ")
    if len(sig_blob) > 0 {
        fmt.Fprintln(os.Stderr, "Yes")
    } else {
        fmt.Fprintln(os.Stderr, "No")
    }

    // Attempt to decode the key blob from base64
    var key []byte
    key, err = base64.StdEncoding.DecodeString(key_blob)
    if err != nil {
        fmt.Fprintln(os.Stderr, "Failed to decode key blob: " + err.Error())
        return
    }

    // Do the same for the signature blob if this is an AKDS record
    var sig []byte
    if record_type == "akds" {
        sig, err = base64.StdEncoding.DecodeString(sig_blob)
        if err != nil {
            fmt.Fprintln(os.Stderr, "Failed to decode signature:  " + err.Error())
            if !config.AcceptUnverified { return }
        }
    }

    // Validate the key blob to ensure it conforms with the OpenSSH authorized_keys format
    var valid bool
    valid, err = validateAuthorizedKeys(string(key))
    if err != nil || !valid {
        fmt.Fprintln(os.Stderr, "Failed to validate keys")
        return
    }

    // Perform signature verification if this is an AKDS record and we have a signature to verify
    if record_type == "akds" {
        verified, err := verifySignature(key, sig, config.pubkey)
        if err != nil {
            fmt.Fprintln(os.Stderr, "Failed to verify AKDS signature: " + err.Error())
            if !config.AcceptUnverified { return }
        }

        if verified && err == nil {
            fmt.Fprintln(os.Stderr, "Successfully verified AKDS data")
        } else {
            fmt.Fprintln(os.Stderr, "Accepting unverified AKDS data")
        }
    }

    // Print out for OpenSSH to handle
    fmt.Print(string(key))
}

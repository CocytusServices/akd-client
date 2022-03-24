package main

import (
    "fmt"
    "os"
    "net"
    "regexp"
    "strings"
    "flag"
    "encoding/base64"
    "github.com/BurntSushi/toml"
    "github.com/ProtonMail/gopenpgp/v2/crypto"
)

// Config file format
type Config struct {
    RecordName string
    Pubkey string
    AcceptUnverified bool
}

type CliArgs struct {
    ConfigPath string
}

// Some patterns for the AKDS record format
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

    return config, nil
}

func main() {
    // Parse CLI args
    args := parseArgs()

    // Load in config
    config, err := loadConfig(args.ConfigPath)
    if err != nil {
        fmt.Fprintln(os.Stderr, "Failed to load config from " + args.ConfigPath)
        return
    }

    // Retrieve AKD(S) records
    records, _ := net.LookupTXT(config.RecordName)

    var key_blob, sig_blob, record_type string
 
    for _, record := range records {
        key_blob = ""
        sig_blob = ""
        record_type = ""

        fmt.Fprintln(os.Stderr, "Record: " + record)
        
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
                fmt.Fprintln(os.Stderr, "Failed to extract signature from AKDS record")
                record_type = ""
                continue
            }

            // Ensure there is a key blob
            if key_blob == "" {
                fmt.Fprintln(os.Stderr, "Failed to extract a key blob from " + strings.ToUpper(record_type) + " record!")
                record_type = ""
                continue
            }
        } else {
            fmt.Fprintln(os.Stderr, "Not a suitable AKD/AKDS record, skipping...")
        }

        // Stop iterating once we've found an eligible record
        if record_type != "" {
            break
        }
    }

    // Make sure a record was chosen
    if record_type == "" {
        fmt.Fprintln(os.Stderr, "No suitable AKD/AKDS record found")
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

    // Perform signature verification if this is an AKDS record and we have a signature to verify
    if record_type == "akds" {
        // Check for missing/empty signature
        if sig == nil || len(sig) == 0 {
            fmt.Fprintln(os.Stderr, "Failed to verify signature: AKDS record has empty or missing signature")
            return
        } else {
            // Parse the pubkey we'll be verifying with
            pgpKey, err := crypto.NewKeyFromArmored(config.Pubkey)
            if err != nil {
                fmt.Fprintln(os.Stderr, "Failed to parse key from config file")
                
                // Exit if we aren't accepting unverified signatures
                if !config.AcceptUnverified { return }
            }

            // Parse our keys and signature as PGP data
            pgpMessage := crypto.NewPlainMessage(key)
            pgpSignature := crypto.NewPGPSignature(sig)
            pgpKeyring, err := crypto.NewKeyRing(pgpKey)
            if err != nil {
                fmt.Fprintln(os.Stderr, "Failed to parse key or signature as valid PGP data")

                // Exit if we aren't accepting unverified signatures
                if !config.AcceptUnverified { return }
            }

            err = pgpKeyring.VerifyDetached(pgpMessage, pgpSignature, crypto.GetUnixTime())
            if err != nil {
                fmt.Fprintln(os.Stderr, "Failed to verify signature: " + err.Error())
        
                // Exit if we aren't allowing unverified signatures
                if !config.AcceptUnverified { return }

                fmt.Fprintln(os.Stderr, "Accepting unverified AKDS data")
            } else {
                fmt.Fprintln(os.Stderr, "Successfully verified AKDS data")
            }
        }
    }

    // Print out for OpenSSH to handle
    fmt.Print(string(key))
}

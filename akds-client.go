package main

import (
    "fmt"
    "os"
    "net"
    "regexp"
    "encoding/base64"
    "github.com/BurntSushi/toml"
    "github.com/ProtonMail/gopenpgp/v2/crypto"
)

// Config file format
type Config struct {
    Pubkey string
    AcceptUnverified bool
}

// Some patterns for the AKDS record format
var header_pattern = regexp.MustCompile("v=(akds?);")
var key_pattern = regexp.MustCompile("k=([A-Za-z0-9+/=]+);")
var sig_pattern = regexp.MustCompile("s=([A-Za-z0-9+/=]+);")

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
    // Load in config
    config, err := loadConfig("config.toml")
    if err != nil {
        fmt.Fprintln(os.Stderr, "Failed to load config from config.toml")
        return
    }

    // Retrieve AKD(S) records
    records, _ := net.LookupTXT("_akds.tem.party")

    key_blob := ""
    sig_blob := ""
    record_type := ""
 
    for _, record := range records {
        fmt.Fprintln(os.Stderr, "Record: " + record)
        
        header := header_pattern.FindStringSubmatch(record)
        if len(header) > 1 {
            switch header[1] {
                case "akds":
                    // Try extract the signature blob
                    sig := sig_pattern.FindStringSubmatch(record)
                    key := key_pattern.FindStringSubmatch(record)
                    if len(sig) > 1 && len(key) > 1 {
                        record_type = "akds"
                        sig_blob = sig[1]
                        key_blob = key[1]
                        break
                    } else if len(key) > 1 {
                        record_type = "akds"
                        key_blob = key[1]

                        fmt.Fprintln(os.Stderr, "Failed to extract signature from AKDS record, but found a valid key blob")
                        break
                    } else {
                        fmt.Fprintln(os.Stderr, "Failed to extract key blob and signature from AKDS record!")
                        break
                    }
                case "akd":
                    key := key_pattern.FindStringSubmatch(record)
                    if len(key) > 1 {
                        record_type = "akd"
                        key_blob = key[1]
                        break
                    } else {
                        fmt.Fprintln(os.Stderr, "Failed to extract a key blob from an AKD record!")
                        break
                    }
                default:
                    fmt.Fprintln(os.Stderr, "Somehow got here, idk how")
                    break
            }
        } else {
            fmt.Fprintln(os.Stderr, "Not a suitable AKD/AKDS record, skipping...")
        }

        // Stop iterating once we've found an eligible record
        if record_type != "" {
            break
        }
    }

    fmt.Fprintln(os.Stderr, "Record type: " + record_type)
    fmt.Fprint(os.Stderr, "Has signature? ")
    if len(sig_blob) > 0 {
        fmt.Fprintln(os.Stderr, "Yes")
    } else {
        fmt.Fprintln(os.Stderr, "No")
    }
    fmt.Fprint(os.Stderr, "Has keys? ")
    if len(key_blob) > 0 {
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
            
            // Exit if we aren't accepting unverified signatures
            if !config.AcceptUnverified { return } 
           
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
        
                // Exit of we aren't allowing unverified signatures
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

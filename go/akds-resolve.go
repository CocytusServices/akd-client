package main

import (
    "fmt"
    "net"
    "regexp"
    "encoding/base64"
    "github.com/BurntSushi/toml"
    //"github.com/ProtonMail/gopenpgp/v2/crypto"
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
        fmt.Println("Failed to load config from config.toml")
        return
    }

    // Retrieve AKD(S) records
    records, _ := net.LookupTXT("_akds.tem.party")

    key_blob := ""
    sig_blob := ""
    record_type := ""
 
    for _, record := range records {
        fmt.Println(record)
        
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

                        fmt.Println("Failed to extract signature from AKDS record, but found a valid key blob")
                        break
                    } else {
                        fmt.Println("Failed to extract key blob and signature from AKDS record!")
                        break
                    }
                case "akd":
                    key := key_pattern.FindStringSubmatch(record)
                    if len(key) > 1 {
                        record_type = "akd"
                        key_blob = key[1]
                        break
                    } else {
                        fmt.Println("Failed to extract a key blob from an AKD record!")
                        break
                    }
                default:
                    fmt.Println("Somehow got here, idk how")
                    break
            }
        } else {
            fmt.Println("Not a suitable AKD/AKDS record, skipping...")
        }

        // Stop iterating once we've found an eligible record
        if record_type != "" {
            break
        }
    }

    fmt.Println("Record type: " + record_type)
    fmt.Println("Signature blob: " + sig_blob)
    fmt.Println("Key blob: " + key_blob)

    // Attempt to decode the key blob from base64
    var key []byte
    key, err = base64.StdEncoding.DecodeString(key_blob)
    if err != nil {
        fmt.Println("Failed to decode key blob: " + err.Error())
        return
    }

    // Do the same for the signature blob if this is an AKDS record
    var sig []byte
    if record_type == "akds" && !config.AcceptUnverified {
        sig, err = base64.StdEncoding.DecodeString(sig_blob)
        if err != nil {
            fmt.Println("Failed to decode signature:  " + err.Error())
            return
        }
    }

    fmt.Println("Decoded key blob: " + string(key))

    // TODO: Verify keys against blob
    //       Accept unverified blob if configured to do so
    //       Output in a format that OpenSSH can understand
}

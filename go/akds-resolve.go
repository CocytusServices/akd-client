package main

import (
    "fmt"
    "net"
    "regexp"
    "encoding/base64"
)

func main() {
    header_pattern := regexp.MustCompile("v=(akds?);")
    key_pattern := regexp.MustCompile("k=([A-Za-z0-9+/=]+);")
    sig_pattern := regexp.MustCompile("s=([A-Za-z0-9+/=]+);")

    records, _ := net.LookupTXT("_akds.tem.party")
    // I'M ok :)

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

    var key []byte
    //var sig []byte
    key, err := base64.StdEncoding.DecodeString(key_blob)
    if err != nil {
        fmt.Println("Failed to decode key blob: " + err.Error())
        return
    }

    /*if record_type == "akds" {
        sig, err = base64.StdEncoding.DecodeString(sig_blob)
        if err != nil {
            fmt.Println("Failed to decode signature:  " + err.Error())
            return
        }
    }*/

    fmt.Println("Decoded key blob: " + string(key))
}

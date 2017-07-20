package main

import ( 
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
)

func check(e error) {
	if e != nil {
		panic(e)
	}
}

// https://stackoverflow.com/a/44688503
func ParseRsaPublicKeyFromPemStr(publicKeyStr string) (*rsa.PublicKey, error) {
    block, _ := pem.Decode([]byte(publicKeyStr))
    if block == nil {
            return nil, errors.New("[-] Failed to decode PEM key.")
    }

    pub, err := x509.ParsePKIXPublicKey(block.Bytes)
    if err != nil {
            return nil, errors.New("[-] Failed to parse public key.")
    }

    // XXX: we'll use this later for private keys too
    switch pub := pub.(type) {
    case *rsa.PublicKey:
            return pub, nil
    default:
            break // fall through
    }
    return nil, errors.New("[-] Key type is not RSA")
}

// import a PEM public key file and return a rsa.PublicKey object
func importKey(publicKeyFile string) (*rsa.PublicKey, error) {
	publicKeyStr, err := ioutil.ReadFile(publicKeyFile)
	if err != nil {
		fmt.Printf("[-] Failed to open/read file %s\n", publicKeyFile)
		return nil, err
	}

	// convert byte array to a string
	p := string(publicKeyStr[:])

	pubKey, err := ParseRsaPublicKeyFromPemStr(p)
	if err != nil {
		fmt.Printf("[-] Failed to open/read file %s\n", publicKeyFile)
		return nil, err
	}
	return pubKey, err
}

func dumpKey(publicKeyFile string) {
	pub, _ := importKey(publicKeyFile)
	fmt.Printf("[*] n = %d\n", pub.N)
	fmt.Printf("[*] e = %d\n", pub.E)
}

func main() {
	// Parse command line arguments
	publicKeyFile := flag.String("publickey", "", "The filename of the public key to attack.")
	verboseMode   := flag.Bool("verbose", false, "Enable verbose output.")
	dumpKeyMode   := flag.Bool("dumpkey", false, "Just dump the RSA integers from a key - n,e,d,p,q.")
	flag.Parse()

	// Print verbose information
	if *verboseMode != false {
		fmt.Printf("[*] goRsaTool\n")
		fmt.Printf("[*] Public Key Filename:\t%s\n", *publicKeyFile)
		fmt.Printf("[*] Verbose Mode:\t%t\n", *verboseMode)
		fmt.Printf("[*] Dump Key Mode:\t%t\n", *dumpKeyMode)
	}

	// Did we get a public key file to read
	if len(*publicKeyFile) > 0 {
		
		if *dumpKeyMode != false {
			dumpKey(*publicKeyFile)
			return
		} else {
			importKey(*publicKeyFile)
		}

	} else {
		fmt.Printf("[-] No public key specified. Nothing to do.\n")
		return
	}


}
package main

import ( 
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"math/big"
	"strconv"
	"github.com/sourcekris/goRsaTool/attacks"
	"github.com/sourcekris/goRsaTool/utils"
)

// https://golang.org/pkg/crypto/x509/#ParsePKIXPublicKey
func ParsePublicRsaKey(keyBytes []byte) (*rsa.PublicKey, error) {
    key, err := x509.ParsePKIXPublicKey(keyBytes)//.Bytes)
    if err != nil {
    	return nil, errors.New("Failed to parse the DER key after decoding.")
    }
   
    switch key := key.(type) {
	case *rsa.PublicKey:
		return key, nil
	default:
		return nil, errors.New("Given key is not an RSA Key")
	}
}

func ParsePrivateRsaKey(keyBytes []byte) (*rsa.PrivateKey, error) {
    key, err := x509.ParsePKCS1PrivateKey(keyBytes)
    if err != nil {
    	return nil, errors.New("Failed to parse the DER key after decoding.")
    }
    return key, nil
}

// import a PEM key file and return a rsa.PrivateKey object
func importKey(keyFile string) (*rsa.PrivateKey, error) {
	// read the key from the disk
	keyStr, err := ioutil.ReadFile(keyFile)
	if err != nil {
		fmt.Printf("[-] Failed to open/read file %s\n", keyFile)
		return nil, err
	}

	// decode the PEM data to extract the DER format key
	block, _ := pem.Decode([]byte(keyStr))
    if block == nil {
            return nil, errors.New("Failed to decode PEM key.")
    }
	
	key, err := ParsePublicRsaKey(block.Bytes)
	if err == nil {
		priv := rsa.PrivateKey{PublicKey: *key}
		return &priv, err
	} 

	priv, err := ParsePrivateRsaKey(block.Bytes)
	if err != nil {
		return nil, errors.New("Failed to parse the key as either a public or private key.")
	}
	return priv, err

}

func dumpKey(key *rsa.PrivateKey) {
	fmt.Printf("[*] n = %d\n", key.N)
	fmt.Printf("[*] e = %d\n", key.E)

	// XXX: Support RSA multiprime [where len(key.Primes) > 2]
	if key.D != nil {
		fmt.Printf("[*] d = %d\n", key.D)
		fmt.Printf("[*] p = %d\n", key.Primes[0])
		fmt.Printf("[*] q = %d\n", key.Primes[1])
	}
}

func main() {
	// Parse command line arguments
	keyFile       := flag.String("key", "", "The filename of the RSA key to attack or dump")
	verboseMode   := flag.Bool("verbose", false, "Enable verbose output.")
	dumpKeyMode   := flag.Bool("dumpkey", false, "Just dump the RSA integers from a key - n,e,d,p,q.")
	createKeyMode := flag.Bool("createkey", false, "Create a public key given an E and N.")
	exponentArg   := flag.String("e","", "The exponent value - for use with createkey flag.")
	modulusArg    := flag.String("n","", "The modulus value - for use with createkey flag.")
	flag.Parse()

	// Print verbose information
	if *verboseMode != false {
		fmt.Printf("[*] goRsaTool\n")
		fmt.Printf("[*] RSA Key Filename:\t%s\n", *keyFile)
		fmt.Printf("[*] Verbose Mode:\t%t\n", *verboseMode)
		fmt.Printf("[*] Dump Key Mode:\t%t\n", *dumpKeyMode)
	}

	// Did we get a public key file to read
	if len(*keyFile) > 0 {
		key, _ := importKey(*keyFile)
		
		if *dumpKeyMode != false {
			dumpKey(key)
			return
		} 
		fmt.Printf("[*] Begin attacks\n")
		// attacks begin here?
		attacks.Factordb(key)

		if key.D != nil {
			privStr := utils.EncodePrivateKey(key)
			fmt.Print(privStr)
			return
		}

	} else {
		if *createKeyMode != false {
			if len(*exponentArg) > 0 && len(*modulusArg) > 0 {
				n := new(big.Int)
				n.SetString(*modulusArg, 10)
				e, err := strconv.Atoi(*exponentArg)
				if err != nil {
					fmt.Printf("[-] Failed converting exponent to integer.")
					return
				}
				
				pub := rsa.PublicKey{N: n, E: e}
				pubStr,_ := utils.EncodePublicKey(&pub)
				fmt.Print(pubStr)		
				return
			} else {
		 		fmt.Printf("[-] No exponent or modulus specified. Nothing to do.\n")
		 		return		
			}
		}
		fmt.Printf("[-] No key file specified. Nothing to do.\n")
		return
	}


}
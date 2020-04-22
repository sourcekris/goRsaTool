package main

import (
	"crypto/rsa"
	"flag"
	"fmt"
	"math/big"
	"strconv"

	"github.com/sourcekris/goRsaTool/attacks"
	"github.com/sourcekris/goRsaTool/utils"
)

// unnatended will run all supported attacks against t that are listed as working in unnatended mode.
func unnatended(t *attacks.RSAStuff) []error {
	var errs []error
	for _, a := range attacks.SupportedAttacks.Supported {
		if a.Unnatended {
			if err := attacks.SupportedAttacks.Execute(a.Name, t); err != nil {
				errs = append(errs, err)
			}
		}
	}

	return errs
}

// listAttacks returns a string containing the list of registered attacks.
func listAttacks() string {
	var res string
	for _, a := range attacks.SupportedAttacks.Supported {
		res = fmt.Sprintf("%s%s\n", res, a.Name)
	}

	return res
}

func main() {
	// Parse command line arguments.
	keyFile := flag.String("key", "", "The filename of the RSA key to attack or dump")
	pastPrimesFile := flag.String("pastprimes", "../pastctfprimes.txt", "The filename of a file containing past CTF prime numbers.")
	verboseMode := flag.Bool("verbose", false, "Enable verbose output.")
	dumpKeyMode := flag.Bool("dumpkey", false, "Just dump the RSA integers from a key - n,e,d,p,q.")
	createKeyMode := flag.Bool("createkey", false, "Create a public key given an E and N.")
	exponentArg := flag.String("e", "", "The exponent value - for use with createkey flag.")
	modulusArg := flag.String("n", "", "The modulus value - for use with createkey flag.")
	cipherText := flag.String("ciphertext", "", "An RSA encrypted binary file to decrypt, necessary for certain attacks.")
	keyList := flag.String("keylist", "", "Comma seperated list of keys for multi-key attacks.")
	ctList := flag.String("ctlist", "", "Comma seperated list of keys for multi-key attacks.")
	attack := flag.String("attack", "all", "Specific attack to try. Specify \"all\" for everything that works unnatended.")
	list := flag.Bool("list", false, "List the attacks supported by the attack flag.")
	flag.Parse()

	// Print verbose information
	if *verboseMode != false {
		// TODO(sewid): Put this behind a configurable logger.
		fmt.Println("[*] goRsaTool")
	}

	if *list {
		fmt.Print(listAttacks())
		return
	}

	// Handle multi key scenarios.
	switch {
	case len(*keyList) > 0 && len(*ctList) == 0:
		// TODO(sewid): Loop around the key list and also do multi key attacks.
	case len(*keyList) > 0 && len(*ctList) > 0:
		// TODO(sewid): hastads broadcast attack.
	}

	// Did we get a public key file to read
	if len(*keyFile) > 0 {
		key, errImport := attacks.ImportKey(*keyFile)

		if errImport != nil {
			return
		}

		var c []byte
		var err error
		if len(*cipherText) > 0 {
			c, err = utils.ReadCipherText(*cipherText)
			if err != nil {
				fmt.Println("[-] Failed reading ciphertext file.")
				return
			}
		}

		targetRSA, _ := attacks.NewRSAStuff(key, c, nil, *pastPrimesFile)

		if *dumpKeyMode != false {
			targetRSA.DumpKey()
			return
		}

		var errs []error
		switch {
		case *attack == "all":
			errs = unnatended(targetRSA)
		case attacks.SupportedAttacks.IsSupported(*attack):
			errs = append(errs, attacks.SupportedAttacks.Execute(*attack, targetRSA))
		default:
			errs = []error{fmt.Errorf("unsupported attack: %v. Use -list to see a list of supported attacks", *attack)}
		}

		for _, e := range errs {
			if e != nil {
				fmt.Printf("attack error: %v\n", e)
			}
		}

		// were we able to solve for the private key?
		if targetRSA.Key.D != nil {
			privStr := attacks.EncodeFMPPrivateKey(&targetRSA.Key)
			fmt.Print(privStr)
			return
		}

		if len(targetRSA.PlainText) > 0 {
			fmt.Println("[+] Recovered plaintext:")
			fmt.Print(string(targetRSA.PlainText))
		}

	} else {
		if *createKeyMode != false {
			if len(*exponentArg) > 0 && len(*modulusArg) > 0 {
				n, _ := new(big.Int).SetString(*modulusArg, 10)

				// TODO(sewid): Support large integers here.
				e, err := strconv.Atoi(*exponentArg)
				if err != nil {
					// TODO(sewid): Support big integers here.
					fmt.Println("failed converting exponent to integer - is it too large?")
					return
				}

				pub := rsa.PublicKey{
					N: n,
					E: e,
				}

				pubStr, _ := attacks.EncodePublicKey(&pub)
				fmt.Println(pubStr)
				return
			} else {
				fmt.Println("[-] No exponent or modulus specified.")
				return
			}
		}
		fmt.Println("no key file specified - use the -key flag to provide a public or private key file")
		return
	}
}

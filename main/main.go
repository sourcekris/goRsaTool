package main

import ( 
	//"crypto/rsa"
	//"errors"
	"flag"
	"fmt"
	"io/ioutil"
)

func check(e error) {
	if e != nil {
		panic(e)
	}
}

// import a PEM public key file and return a rsa.PublicKey object
func importKey(publicKeyFile string) { // (*rsa.PublicKey, error) {
	publicKeyStr, err := ioutil.ReadFile(publicKeyFile)
	check(err)
	fmt.Print(string(publicKeyStr))
}

func dumpKey(publicKeyFile string) {

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
		//pubKey := new(rsa.PublicKey)
		importKey(*publicKeyFile)
	} else {
		fmt.Printf("[-] No public key specified. Nothing to do.\n")
		return
	}
}
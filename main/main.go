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

func main() {
  // Parse command line arguments
  keyFile        := flag.String("key", "", "The filename of the RSA key to attack or dump")
  pastPrimesFile := flag.String("pastprimes", "../pastctfprimes.txt", "The filename of a file containing past CTF prime numbers.")
  verboseMode    := flag.Bool("verbose", false, "Enable verbose output.")
  dumpKeyMode    := flag.Bool("dumpkey", false, "Just dump the RSA integers from a key - n,e,d,p,q.")
  createKeyMode  := flag.Bool("createkey", false, "Create a public key given an E and N.")
  exponentArg    := flag.String("e","", "The exponent value - for use with createkey flag.")
  modulusArg     := flag.String("n","", "The modulus value - for use with createkey flag.")
  cipherText     := flag.String("ciphertext", "", "An RSA encrypted binary file to decrypt, necessary for certain attacks.")
  flag.Parse()

  // Print verbose information
  if *verboseMode != false {
    fmt.Println("[*] goRsaTool")
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

    // attacks begin here
    //targetRSA.FactorDB()
    //targetRSA.SmallQ()
    //targetRSA.NoveltyPrimes()
    //targetRSA.PastCTFPrimes()
    //targetRSA.Hastads()
    //targetRSA.FermatFactorization()
    //targetRSA.Wiener()
    targetRSA.SmallFractions()
    

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

        e, err := strconv.Atoi(*exponentArg)
        if err != nil {
          fmt.Println("[-] Failed converting exponent to integer.")
          return
        }
        
        pub := rsa.PublicKey{
          N: n, 
          E: e,
        }

        pubStr,_ := attacks.EncodePublicKey(&pub)
        fmt.Println(pubStr)   
        return
      } else {
        fmt.Println("[-] No exponent or modulus specified.")
        return    
      }
    }
    fmt.Println("[-] No key file specified. Nothing to do.")
    return
  }
}
#!/bin/bash

#
# This is deprecated by the Makefile test target but still useful to keep around if you want to
# know how a certain attack mode should work. What flags / arguments it needs etc.
#

echo "Testing knownprime attack..."
go run rsatool.go -key examples/knownprime.txt -verbose -attack knownprime
echo "Testing knownprime attack..."
go run rsatool.go -key examples/knownprime2.txt -verbose -p 85413884848837835273799534222229453212517685015009235268389913012627608586153 -attack knownprime
echo "Testing knownprime attack..."
go run rsatool.go -key examples/knownprime2.txt -verbose -p 85413884848837835273799534222229453212517685015009235268389913012627608586153
echo "Testing partiald attack..."
go run rsatool.go -key examples/partiald.txt -verbose -attack partiald
echo "Testing partiald attack..."
go run rsatool.go -key examples/partiald2.txt -verbose -d0 0x136045a22e2c3067b0c283314e43739ec52a09fa783f6887599272ba03682b6e5258714a445084bbc857ea32ad72ffb97c71df1428b30fbf77c3ad3aa21e87619 -attack partiald
echo "Testing partiald attack..."
go run rsatool.go -key examples/partiald3.txt -verbose -attack partiald
echo "Test recovering modulus from signatures and plaintexts..."
go run rsatool.go -ptlist examples/plaintext1.txt,examples/plaintext2.txt -siglist examples/sig1.bin,examples/sig2.bin
echo "Testing notableprimes..."
go run rsatool.go -attack notableprimes -key examples/mersenne.pub
echo "Testing commonfactors..."
go run rsatool.go -attack commonfactors -keylist examples/cf1.pub,examples/cf2.pub
echo "Testing crtsolve..."
go run rsatool.go -attack crtsolver -key examples/crtsolve.key
echo "Testing factordb..."
go run rsatool.go -attack factordb -key examples/factordb.pub
echo "Testing factordb (multiprime)..."
go run rsatool.go -attack factordb -key examples/factordb_multiprime.key
echo "Testing factordb_parse..."
go run rsatool.go -attack factordb -key examples/factordb_parse.pub
echo "Testing fermat..."
go run rsatool.go -attack fermat -key examples/fermat.pub
echo "Testing londahl..."
go run rsatool.go -attack londahl -key examples/londahl.pub
echo "Testing hastads..."
go run rsatool.go -attack hastads -key examples/hastads.pub -ciphertext examples/hastads.cipher
echo "Testing hastadsbroadcast..."
go run rsatool.go -attack hastadsbroadcast -keylist examples/hastadsbroadcast1.key,examples/hastadsbroadcast2.key,examples/hastadsbroadcast3.key
echo "Testing novelty..."
go run rsatool.go -attack novelty -key examples/noveltyprimes.pub
echo "Testing pastctf..."
go run rsatool.go -attack pastctf -key examples/pastctfprimes.pub -pastprimes pastctfprimes.txt
echo "Testing smallq..."
go run rsatool.go -attack smallq -key examples/small_q.pub
echo "Testing wiener..."
go run rsatool.go -attack wiener -key examples/wiener.pub
echo "Testing wiener2..."
go run rsatool.go -attack wienermultiprime -key examples/wiener2-numberlist.txt
echo "Testing wiener variant..."
go run rsatool.go -attack wiener -key examples/wienervariant.key
echo "Testing pollardsp1..."
go run rsatool.go -attack pollardsp1 -key examples/pollardsp1.pub
echo "Testing pollardsrho..."
go run rsatool.go -attack pollardsrho -key examples/pollardrhobrent.pub
echo "Testing pollardrhobrent..."
go run rsatool.go -attack pollardrhobrent -key examples/pollardrhobrent.pub
echo "Testing williamsp1..."
go run rsatool.go -attack williamsp1 -key examples/williamsp1.pub
echo "Testing qicheng..."
go run rsatool.go -attack qicheng -key examples/qicheng.pub
echo "Testing ecm..."
go run rsatool.go -attack ecm -key examples/ecm.pub
echo "Testing franklin reiter related message attack (is currently buggy, skipping)..."
# go run rsatool.go -keylist examples/franklinreiter1.key,examples/franklinreiter2.key -attack franklinreiter
echo "Testing smallfractions attack..."
go run rsatool.go -key examples/smallfraction.pub -attack smallfractions
echo "Testing brokenrsa attack..."
go run rsatool.go -key examples/brokenrsa.txt -attack brokenrsa
echo "Testing manysmallprimes attack..."
go run rsatool.go -numprimes 128 -key examples/manysmallprimes.txt -verbose -attack manysmallprimes
echo "Testing partiald attack..."
go run rsatool.go -key examples/partiald.txt -verbose -attack partiald
echo "Testing commonmodulus attack..."
go run rsatool.go -keylist examples/commonmodulus1.key,examples/commonmodulus2.key -attack commonmodulus
echo "Testing JWT modulus recovery..."
go run rsatool.go -jwtlist examples/jwt1.txt,examples/jwt2.txt
echo "Testing partiald attack..."
go run rsatool.go -key examples/defectivee.txt -verbose -attack defectivee

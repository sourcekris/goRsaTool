#!/bin/bash

echo "Testing notableprimes..."
go run rsatool.go -attack notableprimes -key examples/mersenne.pub
echo "Testing commonfactors..."
go run rsatool.go -attack commonfactors -keylist examples/cf1.pub,examples/cf2.pub
echo "Testing crtsolve..."
go run rsatool.go -attack crtsolver -key examples/crtsolve.key
echo "Testing factordb..."
go run rsatool.go -attack factordb -key examples/factordb.pub
echo "Testing factordb_parse..."
go run rsatool.go -attack factordb -key examples/factordb_parse.pub
echo "Testing fermat..."
go run rsatool.go -attack fermat -key examples/fermat.pub
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
go run rsatool.go -attack wiener -key examples/wiener2-numberlist.txt
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
echo "Testing franklin reiter related message attack..."
go run rsatool.go -keylist examples/franklinreiter1.key,examples/franklinreiter2.key -attack franklinreiter
echo "Testing smallfractions attack..."
go run rsatool.go -key examples/smallfraction.pub -attack smallfractions

#!/bin/bash

#
# This is deprecated by the Makefile test target but still useful to keep around if you want to
# know how a certain attack mode should work. What flags / arguments it needs etc.
#

run_test() {
    if go run rsatool.go "$@" > /dev/null 2>&1; then
        echo "OK"
    else
        echo "FAILED"
    fi
}

echo -n "Testing factordb... "
run_test -attack factordb -key examples/factordb.pub

echo -n "Testing factordb (multiprime)... "
run_test -attack factordb -key examples/factordb_multiprime.key

echo -n "Testing factordb_parse... "
run_test -attack factordb -key examples/factordb_parse.pub

echo -n "Testing encryption oracle modulus recovery... "
run_test -key examples/recover_modulus_from_oracle.txt -attack oraclemodulus

echo -n "Testing knownprime attack... "
run_test -key examples/knownprime.txt -verbose -attack knownprime

echo -n "Testing knownprime attack... "
run_test -key examples/knownprime2.txt -verbose -p 85413884848837835273799534222229453212517685015009235268389913012627608586153 -attack knownprime

echo -n "Testing knownprime attack... "
run_test -key examples/knownprime2.txt -verbose -p 85413884848837835273799534222229453212517685015009235268389913012627608586153

echo -n "Testing partiald attack... "
run_test -key examples/partiald.txt -verbose -attack partiald

echo -n "Testing partiald attack... "
run_test -key examples/partiald2.txt -verbose -d0 0x136045a22e2c3067b0c283314e43739ec52a09fa783f6887599272ba03682b6e5258714a445084bbc857ea32ad72ffb97c71df1428b30fbf77c3ad3aa21e87619 -attack partiald

echo -n "Testing partiald attack... "
run_test -key examples/partiald3.txt -verbose -attack partiald

echo -n "Test recovering modulus from signatures and plaintexts... "
run_test -ptlist examples/plaintext1.txt,examples/plaintext2.txt -siglist examples/sig1.bin,examples/sig2.bin

echo -n "Testing notableprimes... "
run_test -attack notableprimes -key examples/mersenne.pub

echo -n "Testing commonfactors... "
run_test -attack commonfactors -keylist examples/cf1.pub,examples/cf2.pub

echo -n "Testing crtsolve... "
run_test -attack crtsolver -key examples/crtsolve.key

echo -n "Testing fermat... "
run_test -attack fermat -key examples/fermat.pub

echo -n "Testing londahl... "
run_test -attack londahl -key examples/londahl.pub

echo -n "Testing hastads... "
run_test -attack hastads -key examples/hastads.pub -ciphertext examples/hastads.cipher

echo -n "Testing hastadsbroadcast... "
run_test -attack hastadsbroadcast -keylist examples/hastadsbroadcast1.key,examples/hastadsbroadcast2.key,examples/hastadsbroadcast3.key

echo -n "Testing novelty... "
run_test -attack novelty -key examples/noveltyprimes.pub

echo -n "Testing pastctf... "
run_test -attack pastctf -key examples/pastctfprimes.pub -pastprimes pastctfprimes.txt

echo -n "Testing smallq... "
run_test -attack smallq -key examples/small_q.pub

echo -n "Testing wiener... "
run_test -attack wiener -key examples/wiener.pub

echo -n "Testing wiener2... "
run_test -attack wienermultiprime -key examples/wiener2-numberlist.txt

echo -n "Testing wiener variant... "
run_test -attack wiener -key examples/wienervariant.key

echo -n "Testing pollardsp1... "
run_test -attack pollardsp1 -key examples/pollardsp1.pub

echo -n "Testing pollardsrho... "
run_test -attack pollardsrho -key examples/pollardrhobrent.pub

echo -n "Testing pollardrhobrent... "
run_test -attack pollardrhobrent -key examples/pollardrhobrent.pub

echo -n "Testing williamsp1... "
run_test -attack williamsp1 -key examples/williamsp1.pub

echo -n "Testing qicheng... "
run_test -attack qicheng -key examples/qicheng.pub

echo -n "Testing ecm... "
run_test -attack ecm -key examples/ecm.pub

echo -n "Testing franklin reiter related message attack ... "
run_test -keylist examples/franklinreiter1.key,examples/franklinreiter2.key -attack franklinreiter

echo -n "Testing smallfractions attack... "
run_test -attack smallfractions -key examples/smallfraction.pub

echo -n "Testing brokenrsa attack... "
run_test -key examples/brokenrsa.txt -attack brokenrsa

echo -n "Testing manysmallprimes attack... "
run_test -numprimes 128 -key examples/manysmallprimes.txt -verbose -attack manysmallprimes

echo -n "Testing partiald attack... "
run_test -key examples/partiald.txt -verbose -attack partiald

echo -n "Testing commonmodulus attack... "
run_test -keylist examples/commonmodulus1.key,examples/commonmodulus2.key -attack commonmodulus

echo -n "Testing JWT modulus recovery... "
run_test -jwtlist examples/jwt1.txt,examples/jwt2.txt

echo -n "Testing partiald attack... "
run_test -key examples/defectivee.txt -verbose -attack defectivee

echo -n "Testing squaren attack... "
run_test -key examples/squaren.txt -verbose -attack squaren

echo -n "Testing apbq attack... "
run_test -attack apbq -c 7925658536205496145496105864909913841698804988627111589327264207647087371021599624715146199970201133465829350522657974209302809912914631345754196951377499186210285843997712271596344624581015221675171875097569926177625803286344226123963846381574190015963241702836267717409375800964065380453319977184702630199380943887323208760590947005727571317068147150612752450492200509903330780828198170278507237646300390745422616530575815926105334351017776515320327803006039040793248236695404925877281545258818155971734055166797929677109873068535807756177152624750247758835508005818076202086557580467517459509526459954994222107733 -e 65537 -n 13487244535121893803142050477818837867090773702695830915710317760278957239414594039413664548291850262812704115774527807319037549055454297206076220984691198037713266404171521885962954384144959347235389444100155877481802912357132674633884880128105667841540583748054023374707572496059441301607888647200707488850720006967106436804871202685875375533545360179923969238661369697669827308101918547610915038310318070624021040766421119809895329315396306786911716715244892126715656507342336911573357257410955954494465940402266123528623572966813645357903662041629905600305564019544745386629585429281789016899281488949804805973433 -brutemax 256 -hintlist 93690707048761378546891432612703094136123056947302469539537929609977103203297047979247035258430608394707452208616011425282532322585909723570657884371221308059003099931556771434286270777087304918068710314109719362812230577136184026842003856478431246529965153009860967402874474597095746752792361627432414860218876940868512361825848930925319484457710800935318644177626456242425726362235994549199312317555,350764904379382307689364277345531820847061435900641568717267852309239550206853009021463057851572283500639061743382779907334073926896350263764372737516102187386551242814170610855548491050382678574967152668862227883004100688694285204599343384587231111711912140017478382711012082569512738180968957272901804068838492245715405821721219069121893835580859606977908238643354008308976597052630945957874380249432

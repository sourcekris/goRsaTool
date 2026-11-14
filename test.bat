@echo off
setlocal

REM
REM This is deprecated by the Makefile test target but still useful to keep around if you want to
REM know how a certain attack mode should work. What flags / arguments it needs etc.
REM

if exist "C:\msys64\ucrt64\bin" (
    set "PATH=C:\msys64\ucrt64\bin;%PATH%"
)

<nul set /p "=Testing factordb... "
call :run_test -attack factordb -key examples/factordb.pub

<nul set /p "=Testing factordb (multiprime)... "
call :run_test -attack factordb -key examples/factordb_multiprime.key

<nul set /p "=Testing factordb_parse... "
call :run_test -attack factordb -key examples/factordb_parse.pub

<nul set /p "=Testing encryption oracle modulus recovery... "
call :run_test -key examples/recover_modulus_from_oracle.txt -attack oraclemodulus

<nul set /p "=Testing knownprime attack... "
call :run_test -key examples/knownprime.txt -verbose -attack knownprime

<nul set /p "=Testing knownprime attack... "
call :run_test -key examples/knownprime2.txt -verbose -p 85413884848837835273799534222229453212517685015009235268389913012627608586153 -attack knownprime

<nul set /p "=Testing knownprime attack... "
call :run_test -key examples/knownprime2.txt -verbose -p 85413884848837835273799534222229453212517685015009235268389913012627608586153

<nul set /p "=Testing partiald attack... "
call :run_test -key examples/partiald.txt -verbose -attack partiald

<nul set /p "=Testing partiald attack... "
call :run_test -key examples/partiald2.txt -verbose -d0 0x136045a22e2c3067b0c283314e43739ec52a09fa783f6887599272ba03682b6e5258714a445084bbc857ea32ad72ffb97c71df1428b30fbf77c3ad3aa21e87619 -attack partiald

<nul set /p "=Testing partiald attack... "
call :run_test -key examples/partiald3.txt -verbose -attack partiald

<nul set /p "=Test recovering modulus from signatures and plaintexts... "
call :run_test -ptlist examples/plaintext1.txt,examples/plaintext2.txt -siglist examples/sig1.bin,examples/sig2.bin

<nul set /p "=Testing notableprimes... "
call :run_test -attack notableprimes -key examples/mersenne.pub

<nul set /p "=Testing commonfactors... "
call :run_test -attack commonfactors -keylist examples/cf1.pub,examples/cf2.pub

<nul set /p "=Testing crtsolve... "
call :run_test -attack crtsolver -key examples/crtsolve.key

<nul set /p "=Testing fermat... "
call :run_test -attack fermat -key examples/fermat.pub

<nul set /p "=Testing londahl... "
call :run_test -attack londahl -key examples/londahl.pub

<nul set /p "=Testing hastads... "
call :run_test -attack hastads -key examples/hastads.pub -ciphertext examples/hastads.cipher

<nul set /p "=Testing hastadsbroadcast... "
call :run_test -attack hastadsbroadcast -keylist examples/hastadsbroadcast1.key,examples/hastadsbroadcast2.key,examples/hastadsbroadcast3.key

<nul set /p "=Testing novelty... "
call :run_test -attack novelty -key examples/noveltyprimes.pub

<nul set /p "=Testing pastctf... "
call :run_test -attack pastctf -key examples/pastctfprimes.pub -pastprimes pastctfprimes.txt

<nul set /p "=Testing smallq... "
call :run_test -attack smallq -key examples/small_q.pub

<nul set /p "=Testing wiener... "
call :run_test -attack wiener -key examples/wiener.pub

<nul set /p "=Testing wiener2... "
call :run_test -attack wienermultiprime -key examples/wiener2-numberlist.txt

<nul set /p "=Testing wiener variant... "
call :run_test -attack wiener -key examples/wienervariant.key

<nul set /p "=Testing pollardsp1... "
call :run_test -attack pollardsp1 -key examples/pollardsp1.pub

<nul set /p "=Testing pollardsrho... "
call :run_test -attack pollardsrho -key examples/pollardrhobrent.pub

<nul set /p "=Testing pollardrhobrent... "
call :run_test -attack pollardrhobrent -key examples/pollardrhobrent.pub

<nul set /p "=Testing williamsp1... "
call :run_test -attack williamsp1 -key examples/williamsp1.pub

<nul set /p "=Testing qicheng... "
call :run_test -attack qicheng -key examples/qicheng.pub

<nul set /p "=Testing ecm... "
call :run_test -attack ecm -key examples/ecm.pub

<nul set /p "=Testing franklin reiter related message attack ... "
call :run_test -keylist examples/franklinreiter1.key,examples/franklinreiter2.key -attack franklinreiter

<nul set /p "=Testing smallfractions attack... "
call :run_test -attack smallfractions -key examples/smallfraction.pub

<nul set /p "=Testing brokenrsa attack... "
call :run_test -key examples/brokenrsa.txt -attack brokenrsa

<nul set /p "=Testing manysmallprimes attack... "
call :run_test -numprimes 128 -key examples/manysmallprimes.txt -verbose -attack manysmallprimes

<nul set /p "=Testing partiald attack... "
call :run_test -key examples/partiald.txt -verbose -attack partiald

<nul set /p "=Testing commonmodulus attack... "
call :run_test -keylist examples/commonmodulus1.key,examples/commonmodulus2.key -attack commonmodulus

<nul set /p "=Testing JWT modulus recovery... "
call :run_test -jwtlist examples/jwt1.txt,examples/jwt2.txt

<nul set /p "=Testing partiald attack... "
call :run_test -key examples/defectivee.txt -verbose -attack defectivee

<nul set /p "=Testing squaren attack... "
call :run_test -key examples/squaren.txt -verbose -attack squaren

<nul set /p "=Testing apbq attack... "
call :run_test -attack apbq -c 7925658536205496145496105864909913841698804988627111589327264207647087371021599624715146199970201133465829350522657974209302809912914631345754196951377499186210285843997712271596344624581015221675171875097569926177625803286344226123963846381574190015963241702836267717409375800964065380453319977184702630199380943887323208760590947005727571317068147150612752450492200509903330780828198170278507237646300390745422616530575815926105334351017776515320327803006039040793248236695404925877281545258818155971734055166797929677109873068535807756177152624750247758835508005818076202086557580467517459509526459954994222107733 -e 65537 -n 13487244535121893803142050477818837867090773702695830915710317760278957239414594039413664548291850262812704115774527807319037549055454297206076220984691198037713266404171521885962954384144959347235389444100155877481802912357132674633884880128105667841540583748054023374707572496059441301607888647200707488850720006967106436804871202685875375533545360179923969238661369697669827308101918547610915038310318070624021040766421119809895329315396306786911716715244892126715656507342336911573357257410955954494465940402266123528623572966813645357903662041629905600305564019544745386629585429281789016899281488949804805973433 -brutemax 256 -hintlist 93690707048761378546891432612703094136123056947302469539537929609977103203297047979247035258430608394707452208616011425282532322585909723570657884371221308059003099931556771434286270777087304918068710314109719362812230577136184026842003856478431246529965153009860967402874474597095746752792361627432414860218876940868512361825848930925319484457710800935318644177626456242425726362235994549199312317555,350764904379382307689364277345531820847061435900641568717267852309239550206853009021463057851572283500639061743382779907334073926896350263764372737516102187386551242814170610855548491050382678574967152668862227883004100688694285204599343384587231111711912140017478382711012082569512738180968957272901804068838492245715405821721219069121893835580859606977908238643354008308976597052630945957874380249432

<nul set /p "=Testing rabin attack... "
call :run_test -key examples/rabin.txt -attack rabin

<nul set /p "=Testing dleak attack... "
call :run_test -key examples/dleak.txt -attack dleak

exit /b 0

:run_test
go run rsatool.go %* >nul 2>&1
if %ERRORLEVEL% equ 0 (
    echo OK
) else (
    echo FAILED
)
exit /b 0

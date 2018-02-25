# Fixed Logica Programs
This folder contains programs from the Logica breach but fixed up to
make them work. Often the code in the Logica writeups were crippled
and/or incomplete. This folder attempts to fix these broken scripts so
they work. The purpose of this is for learning and historical reasons.

## DeFeNeStRaTe.C

This program was barely changed:
'''
/* Changed by SOF 
PathName = (memcmp(environ[0], "PAYLOAD=", 8) == 0)? strdup(VICTIM) : argv[0]; 
*/
if(memcmp(environ[0], "PAYLOAD=", 8) == 0) {
  PathName = strdup(VICTIM);
} else {
  PathName = argv[0];
}
'''

## tinyd.c

This program is basically a re-write of `DeFeNeStRaTe.C` to make it more
legible and easier to follow. it eliminates some of the fluff and some
of the extraneous code not being used.

## tst.c

This is a simple C program used to test tinyd/DeFeNeStRaTe.

To use this program to test tinyd/DeFeNeStRaTe you must do steps 1
through 4 below (If your 'shellcode' doesn't need APF authorization you
can skip the steps below and just compile it):
 1. Create an HFS/ZFS dataset
  * use ishell option `File_systems` to create the HFS/ZFS option
 2. Add that dataset to APF libraries
  * in sdsf `/setprog apf,add,dsname=<HFS/ZFS dataset name>,volume=<ZFS/HFS dataset volume>`
 3. Mount that dataset using TSO MOUNT command
  * `MOUNT filesystem('<HFS dataset>') MOUNTPOINT('/APF') TYPE(<HFS or ZFS>)`
 4. Give your user account the ability to make APF authorized omvs programs using RACF commands in TSO
  * `RDEFINE FACILITY BPX.FILEATTR.APF UACC(NONE)`
  * `PERMIT BPX.FILEATTR.APF CLASS(FACILITY) ID(<your userid>) ACCESS(READ)`
  * `SETROPTS RACLIST(FACILITY) REFRESH`

Once youve done all that you can compile and set tst APF authorized with:
 `xlc -Wc,debug -Wl,AC=1 -o tst tst.c; extattr +a ./tst`

## kuku.rx

This is the fixed up version of kuku.rx. Take any compiled REXX exec
with the setuid bit set and kuku.rx will execute commands as that user.

Change the line:
```spawn /usr/lpp/netview/v5r1/bin/cnmeunix 0 . parm. env.```
and replace `/usr/lpp/netview/v5r1/bin/cnmeunix` with any compile REXX
exec and it will run any commands you place after `address sh 'id'`


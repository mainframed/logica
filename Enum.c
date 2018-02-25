#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <pwd.h>

int main(int argc, char *argv[]) {
    unsigned int a,b;
    if (argc <2) exit(1);
    a = atoi(argv[1]); 
    b=(argc>2)?atoi(argv[2]) : (~0); 
    printf("%u...%u\n", a,b); 
    while (a <= b) {
        struct passwd *pw = getpwuid((uid_t)a);
        // https://www.ibm.com/support/knowledgecenter/SSLTBW_1.13.0/com.ibm.zos.r13.bpxbd00/rtgtpu.htm
        if (pw!=NULL) {
            printf("%u %u:%u %s %s %s\n", a, (unsigned int)pw->pw_uid, (unsigned int)pw->pw_gid, pw->pw_name, pw->pw_dir, pw->pw_shell);
        }
        a++;
    }
    return 0;
}
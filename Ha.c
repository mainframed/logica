#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
int main(int argc, char *argv[]) { 
    if (argc<3)exit(1 ); 
    setgid(atoi(argv[2])); 
    setuid(atoi(argv[1])); 
    setgid(atoi(argv[2])); 
    execl("/bin/sh","sh",NULL); 
    return O;
}

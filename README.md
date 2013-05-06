## Logica Investigation

**Description**: In this repository is a collection of files outlined/documented in the various files included within the alleged Logica breach. Most of the files are complete (typos notwithstanding) and incomplete files contain whatever was documented in the investigation paperwork.

##WHY?

I decided to document these files here due to the historical nature of the breach. It is the first publicly documented IBM z/OS breach in which the some of the code is actually available. It also serves as educational resources to those wanting to get interested in testing/auditing mainframes and mainframe security. 

##The Files

**aptitup.jcl**: A JES job (JCL) file which executes a file in the OMVS (aka UNIX) environment using BPXBATCH. 

**Enum.c**: An OMVS program to enumerate users and execute a shell. 

**go.rx**: A REXX script used to escalate privileges to the UID/GID supplied to the script. It is assumed this program is running with an appropriate setuid.

**Ha.C**: A C program used to escalate privileges to the UID/GID supplied in the script. It is assumed this program would be run with an appropriate setuid. 

**kuku.rx**: A REXX script which exploits a previously unknown vulnerability in CNMEUNIX (a program in OMVS with setuid). **this code is only a snippet as that is all that is available**.

**nop.jcl**: A JCL file which "does nothing" ;)

**Tfy.source.backdoor**: A ASM program which changes ACEE settings. 

**tsocmd.rx**: A REXX script which executes TSO commands. This is different from the /bin/tso command as it can execute (i.e. authorized programs). This script is freely available from IBM but was found during the investigation. 

**utcam.sh**: BASH script which when run send commands to a remote listening web server. 

**vc242**: Turns on and off the JSCBAUTH bit depending on the contents of Register 0. (thanks @BarrySchrager1)



#ifndef _CMN_FLAGS_
#define _CMN_FLAGS_
#define MAY_EXEC		0x00000001
#define MAY_WRITE		0x00000002
#define MAY_READ		0x00000004
#define MY_PAGE_SIZE    4096
#define D_OPTION    	1
#define P_OPTION    	2
#define N_OPTION    	4
#define S_OPTION    	8


struct argStructure{
        char *infile1;
        char *infile2;
        char *outfile;
        int flags;
};
#endif
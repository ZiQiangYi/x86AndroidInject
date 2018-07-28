#ifndef __ATTACH_H__
#define __ATTACH_H__

const char	*g_szLogPath = "/mnt/shared/Applications/attach.log";
#define		MAX_PACKET_SIZE					0x400

char		g_szBuffer[MAX_PACKET_SIZE * 4];
typedef		unsigned char		BYTE;
typedef		unsigned short		WORD;
typedef		unsigned int		DWORD;
typedef		unsigned long long 	QWORD;
typedef		wchar_t				WCHAR;

#define		MAX_BREAK						0x100
#define		MAX_ORGDATA_SIZE				0x0C

DWORD		g_pBreakPointAddr[MAX_BREAK];
BYTE		g_pOriginalData[MAX_BREAK][MAX_ORGDATA_SIZE];


#define		R_EDI							(ucont->uc_mcontext.gregs[REG_EDI])
#define		R_ESI							(ucont->uc_mcontext.gregs[REG_ESI])
#define		R_EBP							(ucont->uc_mcontext.gregs[REG_EBP])
#define		R_ESP							(ucont->uc_mcontext.gregs[REG_ESP])
#define		R_EBX							(ucont->uc_mcontext.gregs[REG_EBX])
#define		R_EDX							(ucont->uc_mcontext.gregs[REG_EDX])
#define		R_ECX							(ucont->uc_mcontext.gregs[REG_ECX])
#define		R_EAX							(ucont->uc_mcontext.gregs[REG_EAX])
#define		R_EIP							(ucont->uc_mcontext.gregs[REG_EIP])

#define     PUSHREG(x)						R_ESP-=4;  *(DWORD*)R_ESP =x; R_EIP++
#define		NOP(x)							R_EIP += x
#endif	//__ATTACH_H__
#include <arpa/inet.h>
#include <dirent.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <jni.h>
#include <netdb.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <android/log.h>
#include <fstream>
#include <ucontext.h>
#include "attach.h"

pthread_mutex_t		g_handler_stack_mutex_ = PTHREAD_MUTEX_INITIALIZER;

void	Log(const char *szFormat, ...)
{
	uint8_t			pbSend[1024];
	va_list			arg;
	struct timespec	ts;
	struct tm		*timeinfo;

	clock_gettime(CLOCK_REALTIME, &ts);
	timeinfo = localtime(&ts.tv_sec);

	va_start(arg, szFormat);
	vsprintf(g_szBuffer, szFormat, arg);
	va_end(arg);

#ifndef LGT_RELEASE
	//LOG("%s", g_szBuffer);
	FILE			*fp;

	if (g_szBuffer[0])
	{
		if (!strcmp(g_szBuffer, "Init"))
		{
			fp = fopen(g_szLogPath, "w");
			if (!fp)
				return;
			fclose(fp);
			return;
		}
		fp = fopen(g_szLogPath, "a+");
		if (!fp)
			return;
		fprintf(fp, "[ %02d:%02d:%02d:%03d ]  %s\r\n", timeinfo->tm_hour, timeinfo->tm_min, timeinfo->tm_sec, (int)(ts.tv_nsec / 1000000), g_szBuffer);
		fclose(fp);
	}
#endif
}


void	DumpStack(DWORD dwAddr, DWORD dwDepth)
{
	DWORD	i;

	for (i = 0; i < dwDepth; i++)
	{
		Log("Stack %04X: %08X", i * 4, *(DWORD *)(dwAddr + i * 4));
	}
}

const int kExceptionSignals[] = {
	SIGSEGV, SIGABRT, SIGFPE, SIGILL, SIGBUS, SIGTRAP, SIGINT
};


const int kNumHandledSignals =
sizeof(kExceptionSignals) / sizeof(kExceptionSignals[0]);

void SignalHandler(int sig, siginfo_t*info, void*context)
{
	ucontext_t      *ucont = (ucontext_t *)context;
	int i = 0;

	Log("SignalHandler =%08x breakpoint=%08x", R_EIP, g_pBreakPointAddr[0]);
 
	pthread_mutex_lock(&g_handler_stack_mutex_);
	for (i = 0; i < MAX_BREAK; i++)
	{
		if (R_EIP == g_pBreakPointAddr[i] + 3)
			break;
	}

	if (i >= MAX_BREAK)
	{
		Log("No breakpoint %x %d", R_EIP, sig);
		pthread_mutex_unlock(&g_handler_stack_mutex_);
		return;
	}
	//Restore eax and esp
	R_EAX = *(DWORD*)R_ESP;
	R_ESP += 4;

	switch (i)
	{
		case 0:
		{
			Log("Breakpoint seted!");
// 			PUSHREG(R_EBP);
// 			R_EBP = R_ESP;
// 			PUSHREG(R_EBX);
// 			R_ESP &= 0xFFFFFFF0;
// 			NOP(2);
			R_EAX = 1;
			R_EIP = *(DWORD *)R_ESP;
			R_ESP += 4;
			Log("When set breaked R_EBP=%08x R_ESP=%08x R_EIP=%08x R_EAX =%08x ", R_EBP, R_ESP, R_EIP,R_EAX );
		}
		break;
	}
	pthread_mutex_unlock(&g_handler_stack_mutex_);
}

void RegisterSignalHandler()
{
	struct sigaction	trap_action, old_action;
	trap_action.sa_sigaction = SignalHandler;								//determine signal handler
	trap_action.sa_flags = SA_SIGINFO | SA_RESTART | SA_NODEFER;			
	sigemptyset(&trap_action.sa_mask);										//there is no blocking signal while treat this signal

	for (int i = 0; i < kNumHandledSignals; ++i)
		sigaddset(&trap_action.sa_mask, kExceptionSignals[i]);

	for (int i = 0; i < kNumHandledSignals; ++i)
	{
		sigaction(kExceptionSignals[i], &trap_action, &old_action);
		Log("old action ---- %d %08X %08X %08X %08X", kExceptionSignals[i], (DWORD)old_action.sa_handler, (DWORD)old_action.sa_sigaction, old_action.sa_mask, old_action.sa_flags);
	}
}

void SetBreakpoint(DWORD nNo, DWORD addr)
{
	BYTE		newBytes[12];
	DWORD		bOffset;
	int			nNewByteNum;

	Log("Set Breakpoint");


	if (nNo >= MAX_BREAK)
	{
		Log("breakpoint number range out %d\n", nNo);
		return;
	}

	if (g_pBreakPointAddr[nNo] == addr)
	{
		Log("breakpoint already set %d\n", nNo);
		return;
	}
  
	

	g_pBreakPointAddr[nNo] = addr;

	//Set breakpoint
	BYTE	bkcode[] =
	{
		0x50,				// push eax
		0x31, 0xC0,			// xor eax, eax
		0x8B, 0,			// mov eax, dword ptr [eax]
	};

	nNewByteNum = sizeof(bkcode);
	memcpy(newBytes, bkcode, nNewByteNum);

	mprotect((void*)(addr & 0xFFFFF000), 0x1000, PROT_READ | PROT_WRITE | PROT_EXEC); //page size 0x1000 
	//Backup original data
	memcpy((void*)g_pOriginalData[nNo], (void*)addr, MAX_ORGDATA_SIZE);
	memcpy((void*)addr, newBytes, nNewByteNum);
	mprotect((void*)(addr & 0xFFFFF000), 0x1000, PROT_READ | PROT_EXEC);
	DumpStack(addr, 0x10);
}

void	RestoreBreakpoint(DWORD nNo)
{
	if (!g_pBreakPointAddr[nNo])
	{
		Log("Restore point error %d\n", nNo);
		return;
	}

	mprotect((void*)(g_pBreakPointAddr[nNo] & 0xFFFFF000), 0x1000, PROT_READ | PROT_WRITE | PROT_EXEC);
	memcpy((void*)g_pBreakPointAddr[nNo], (void*)g_pOriginalData[nNo], MAX_ORGDATA_SIZE);
	mprotect((void*)(g_pBreakPointAddr[nNo] & 0xFFFFF000), 0x1000, PROT_READ | PROT_EXEC);
	g_pBreakPointAddr[nNo] = 0;

	memset((void*)g_pOriginalData[nNo], 0, MAX_ORGDATA_SIZE);
}




void* get_module_base(pid_t pid, const char* module_name)
{
	FILE *fp;
	long addr = 0;
	char *pch;
	char filename[32];
	char line[1024];

	if (pid < 0) {
		/* self process */
		snprintf(filename, sizeof(filename), "/proc/self/maps");
	}
	else {
		snprintf(filename, sizeof(filename), "/proc/%d/maps", pid);
	}

	fp = fopen(filename, "r");
	Log("filename %s", filename);
	Log("finding %s", module_name);

	if (fp != NULL) {
		while (fgets(line, sizeof(line), fp)) {
			if (strstr(line, module_name)) {
				printf("CCC\n");
				pch = strtok(line, "-");
				addr = strtoul(pch, NULL, 16);

				if (addr == 0x8000)
					addr = 0;

				break;
			}
		}

		fclose(fp);
	}

	return (void *)addr;

}

void* runningThread(void *)
{
	sleep(5);
	DWORD plibnative = (DWORD)get_module_base(-1, "libnative-lib.so");
	Log("libnative %08x\n", plibnative);
	DumpStack(plibnative + 0x6b00, 0x10);
	SetBreakpoint(0, plibnative + 0x6b00);
}

__attribute__((constructor))
void	Init()
{
 	Log("Init"); 
	Log("hook-sigaction"); 
	RegisterSignalHandler();

	//Find lib-native.so addresss
	pthread_t tid;
	pthread_create(&tid, 0, runningThread, 0);
}

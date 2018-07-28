#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>
#include <dirent.h>
#include <string.h>
#include <dlfcn.h>
#include <elf.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <asm/ptrace.h>
#include <sys/ptrace.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <asm/user.h>
#include <sys/uio.h>
#include <android/log.h>

//#include "inject.h"
//#include "../../Global/global.h"

#define		GAME_PACKAGE_NAME		"com.example.user.myapplication"
#define		GAME_MAIN_ACTIVITY		".MainActivity"

#if defined(__i386__)
#define pt_regs         user_regs_struct
#endif

#define ENABLE_DEBUG 1

#if ENABLE_DEBUG
#define  LOG_TAG "INJECT"
#define  LOGD(fmt, args...)  __android_log_print(ANDROID_LOG_FATAL,LOG_TAG, fmt, ##args)
#define DEBUG_PRINT(format,args...) \
    Log(format, ##args)
#else
#define DEBUG_PRINT(format,args...)
#endif

#define CPSR_T_MASK     ( 1u << 5 )

const char *libc_path = "/system/lib/libc.so";
const char *linker_path = "/system/bin/linker";

#define		MAX_PACKET_SIZE					0x400

char		g_szBuffer[MAX_PACKET_SIZE * 4];
const char	*g_szLogPath = "/mnt/shared/Applications/inject.log";

int ptrace_setregs(pid_t pid, struct pt_regs * regs);
int ptrace_continue(pid_t pid);

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

int ptrace_readdata(pid_t pid, uint8_t *src, uint8_t *buf, size_t size)
{
	uint32_t i, j, remain;
	uint8_t *laddr;

	union u {
		long val;
		char chars[sizeof(long)];
	} d;

	j = size / 4;
	remain = size % 4;

	laddr = buf;

	for (i = 0; i < j; i++) {
		d.val = ptrace(PTRACE_PEEKTEXT, pid, src, 0);
		memcpy(laddr, d.chars, 4);
		src += 4;
		laddr += 4;
	}

	if (remain > 0) {
		d.val = ptrace(PTRACE_PEEKTEXT, pid, src, 0);
		memcpy(laddr, d.chars, remain);
	}

	return 0;
}

int ptrace_writedata(pid_t pid, uint8_t *dest, uint8_t *data, size_t size)
{
	uint32_t i, j, remain;
	uint8_t *laddr;

	union u {
		long val;
		char chars[sizeof(long)];
	} d;

	j = size / 4;
	remain = size % 4;

	laddr = data;

	for (i = 0; i < j; i++) {
		memcpy(d.chars, laddr, 4);
		ptrace(PTRACE_POKETEXT, pid, dest, d.val);

		dest += 4;
		laddr += 4;
	}

	if (remain > 0) {
		d.val = ptrace(PTRACE_PEEKTEXT, pid, dest, 0);
		for (i = 0; i < remain; i++) {
			d.chars[i] = *laddr++;
		}

		ptrace(PTRACE_POKETEXT, pid, dest, d.val);
	}

	return 0;
}
  
long ptrace_call(pid_t pid, uint32_t addr, long *params, uint32_t num_params, struct user_regs_struct * regs)
{
	regs->esp -= (num_params) * sizeof(long);
	ptrace_writedata(pid, (uint8_t *)regs->esp, (uint8_t *)params, (num_params) * sizeof(long));

	long tmp_addr = 0x00;
	regs->esp -= sizeof(long);
	ptrace_writedata(pid, (uint8_t *)regs->esp, (uint8_t *)&tmp_addr, sizeof(tmp_addr));

	regs->eip = addr;

	if (ptrace_setregs(pid, regs) == -1
		|| ptrace_continue(pid) == -1) {
		DEBUG_PRINT("error\n");
		return -1;
	}

	int stat = 0;
	waitpid(pid, &stat, WUNTRACED);
	while (stat != 0xb7f) {
		if (ptrace_continue(pid) == -1) {
			DEBUG_PRINT("error\n");
			return -1;
		}
		waitpid(pid, &stat, WUNTRACED);
	}

	return 0;
} 

int ptrace_getregs(pid_t pid, struct pt_regs * regs)
{
	if (ptrace(PTRACE_GETREGS, pid, NULL, regs) < 0) {
		DEBUG_PRINT("ptrace_getregs: Can not get register values");
		return -1;
	}

	return 0;
}

int ptrace_setregs(pid_t pid, struct pt_regs * regs)
{
	if (ptrace(PTRACE_SETREGS, pid, NULL, regs) < 0) {
		DEBUG_PRINT("ptrace_setregs: Can not set register values");
		return -1;
	}

	return 0;
}

int ptrace_continue(pid_t pid)
{
	if (ptrace(PTRACE_CONT, pid, NULL, 0) < 0) {
		DEBUG_PRINT("ptrace_cont");
		return -1;
	}

	return 0;
}

int ptrace_attach(pid_t pid)
{
	if (ptrace(PTRACE_ATTACH, pid, NULL, 0) < 0) {
		DEBUG_PRINT("ptrace_attach");
		return -1;
	}

	int status = 0;
	waitpid(pid, &status, WUNTRACED);

	return 0;
}

int ptrace_detach(pid_t pid)
{
	if (ptrace(PTRACE_DETACH, pid, NULL, 0) < 0) {
		DEBUG_PRINT("ptrace_detach");
		return -1;
	}

	return 0;
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

	if (fp != NULL) {
		while (fgets(line, sizeof(line), fp)) {
			if (strstr(line, module_name)) {
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

void* get_remote_addr(pid_t target_pid, const char* module_name, void* local_addr)
{
	void* local_handle, *remote_handle;

	local_handle = get_module_base(-1, module_name);
	remote_handle = get_module_base(target_pid, module_name);

	DEBUG_PRINT("[+] get_remote_addr: local[%x], remote[%x]\n", local_handle, remote_handle);

	uint8_t * ret_addr = (uint8_t *)((uint32_t)local_addr + (uint32_t)remote_handle - (uint32_t)local_handle);
	 
	return ret_addr;
}

int find_pid_of(const char *process_name)
{
	int id;
	pid_t pid = -1;
	DIR* dir;
	FILE *fp;
	char filename[32];
	char cmdline[256];

	struct dirent * entry;

	if (process_name == NULL)
		return -1;

	dir = opendir("/proc");
	if (dir == NULL)
		return -1;

	while ((entry = readdir(dir)) != NULL) {
		id = atoi(entry->d_name);
		if (id != 0) {
			sprintf(filename, "/proc/%d/cmdline", id);
			fp = fopen(filename, "r");
			if (fp) {
				fgets(cmdline, sizeof(cmdline), fp);
				fclose(fp);

				if (strcmp(process_name, cmdline) == 0) {
					/* process found */
					pid = id;
					break;
				}
			}
		}
	}

	closedir(dir);
	return pid;
}

long ptrace_retval(struct pt_regs * regs)
{ 
	return regs->eax; 
}

long ptrace_ip(struct pt_regs * regs)
{ 
	return regs->eip; 
}

int ptrace_call_wrapper(pid_t target_pid, const char * func_name, void * func_addr, long * parameters, int param_num, struct pt_regs * regs)
{
	DEBUG_PRINT("[+] Calling %s in target process.\n", func_name);
	if (ptrace_call(target_pid, (uint32_t)func_addr, parameters, param_num, regs) == -1)
		return -1;

	if (ptrace_getregs(target_pid, regs) == -1)
		return -1;
	DEBUG_PRINT("[+] Target process returned from %s, return value=%x, pc=%x \n",
		func_name, ptrace_retval(regs), ptrace_ip(regs));
	return 0;
}

int inject_remote_process(pid_t target_pid, const char *library_path, const char *function_name, const char *param, size_t param_size)
{
	int ret = -1;
	void *mmap_addr, *dlopen_addr, *dlsym_addr, *dlclose_addr, *dlerror_addr;
	void *local_handle, *remote_handle, *dlhandle;
	uint8_t *map_base = 0;
	uint8_t *dlopen_param1_ptr, *dlsym_param2_ptr, *saved_r0_pc_ptr, *inject_param_ptr, *remote_code_ptr, *local_code_ptr;

	struct pt_regs regs, original_regs;
	extern uint32_t _dlopen_addr_s, _dlopen_param1_s, _dlopen_param2_s, _dlsym_addr_s, \
		_dlsym_param2_s, _dlclose_addr_s, _inject_start_s, _inject_end_s, _inject_function_param_s, \
		_saved_cpsr_s, _saved_r0_pc_s;

	uint32_t code_length;
	long parameters[10];

	DEBUG_PRINT("[+] Injecting process: %d\n", target_pid);

	if (ptrace_attach(target_pid) == -1)
		return ret;

	if (ptrace_getregs(target_pid, &regs) == -1)
		return ret;

	/* save original registers */
	memcpy(&original_regs, &regs, sizeof(regs));

	mmap_addr = get_remote_addr(target_pid, libc_path, (void *)mmap);
	DEBUG_PRINT("[+] Remote mmap address: %x\n", mmap_addr);

	/* call mmap */
	parameters[0] = 0;  // addr
	parameters[1] = 0x4000; // size
	parameters[2] = PROT_READ | PROT_WRITE | PROT_EXEC;  // prot
	parameters[3] = MAP_ANONYMOUS | MAP_PRIVATE; // flags
	parameters[4] = 0; //fd
	parameters[5] = 0; //offset

	if (ptrace_call_wrapper(target_pid, "mmap", mmap_addr, parameters, 6, &regs) == -1)
		return ret;

	map_base = (uint8_t *)ptrace_retval(&regs);

	dlopen_addr = get_remote_addr(target_pid, linker_path, (void *)dlopen);
	dlsym_addr = get_remote_addr(target_pid, linker_path, (void *)dlsym);
	dlclose_addr = get_remote_addr(target_pid, linker_path, (void *)dlclose);
	dlerror_addr = get_remote_addr(target_pid, linker_path, (void *)dlerror);

	DEBUG_PRINT("[+] Get imports: dlopen: %x, dlsym: %x, dlclose: %x, dlerror: %x\n",
		dlopen_addr, dlsym_addr, dlclose_addr, dlerror_addr);

	DEBUG_PRINT("library path = %s\n", library_path);
	ptrace_writedata(target_pid, map_base, (uint8_t *)library_path, strlen(library_path) + 1);

	parameters[0] = (long)map_base;
	parameters[1] = RTLD_NOW | RTLD_GLOBAL;

	if (ptrace_call_wrapper(target_pid, "dlopen", dlopen_addr, parameters, 2, &regs) == -1)
		return ret;

	void *sohandle = (void *)ptrace_retval(&regs);
	DEBUG_PRINT("so handle = %x", sohandle);
	if ((unsigned int)sohandle == 0x7fffffff)
		return ret;

	ptrace_setregs(target_pid, &original_regs);
	ptrace_detach(target_pid);
	ret = 0;

	return ret;
}

void runApp(const char *szPackage, const char *szActivity)
{
	char szCmd[200];
	sprintf(szCmd, "am start -a android.intent.action.MAIN -n %s/%s", szPackage, szActivity);
	system(szCmd);
}

void killProcess(pid_t pid)
{
	char szCmd[200];
	sprintf(szCmd, "kill %d", pid);
	system(szCmd);
}

void* attachThread(void *arg)
{
	pid_t target_pid = -1;
 	while (target_pid == -1)
		target_pid = find_pid_of(GAME_PACKAGE_NAME);

 	DEBUG_PRINT("target_pid = %d\n", target_pid);

	int ret = inject_remote_process(target_pid, "/mnt/shared/Applications/libattach.so", "hook_entry", "I'm parameter!", strlen("I'm parameter!"));

	return (void *)ret;
}

int main(int argc, char** argv) {
	pid_t target_pid = -1;

	Log("Init");

	int status = -1;
	do 
	{
 		// kill old process
		target_pid = find_pid_of("com.example.user.myapplication");
		DEBUG_PRINT("prev target_pid = %d\n", target_pid);
		if (target_pid != -1)
		{
			killProcess(target_pid);
			sleep(1);
		}

 		pthread_t tid;
		pthread_create(&tid, 0, attachThread, 0);
		runApp(GAME_PACKAGE_NAME, GAME_MAIN_ACTIVITY);
		pthread_join(tid, (void **)&status);
		Log("thread join %d", status);
	} while (status == -1);
	
	return 0;
}


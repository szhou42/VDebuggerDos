#ifndef VDBG_HEADER
#define VDBG_HEADER

#include <windows.h>
#include <string>
#include <iostream>
#include <iomanip>
#include <map>
#include <Dbghelp.h>
#include <psapi.h>
#include <winnt.h>
#include <vector>
#include <fstream>
#include <sstream>
using namespace std;
#define BUFSIZE   512

#define STEP_IN   0
#define STEP_OVER 1
#define INITIAL_STATE -1

struct MY_SYMBOL_INFO
{
	DWORD Address;
	string name;
	int   nSize;
	int   type;
	ULONG64 modBase;
};
enum BaseTypeEnum {
   btNoType = 0,
   btVoid = 1,
   btChar = 2,
   btWChar = 3,
   btInt = 6,
   btUInt = 7,
   btFloat = 8,
   btBCD = 9,
   btBool = 10,
   btLong = 13,
   btULong = 14,
   btCurrency = 25,
   btDate = 26,
   btVariant = 27,
   btComplex = 28,
   btBit = 29,
   btBSTR = 30,
   btHresult = 31
};
enum SymTagEnum
{
    SymTagNull,
    SymTagExe,
    SymTagCompiland,
    SymTagCompilandDetails,
    SymTagCompilandEnv,
    SymTagFunction,
    SymTagBlock,
    SymTagData,
    SymTagAnnotation,
    SymTagLabel,
    SymTagPublicSymbol,
    SymTagUDT,
    SymTagEnum,
    SymTagFunctionType,
    SymTagPointerType,
    SymTagArrayType,
    SymTagBaseType,
    SymTagTypedef,
    SymTagBaseClass,
    SymTagFriend,
    SymTagFunctionArgType,
    SymTagFuncDebugStart,
    SymTagFuncDebugEnd,
    SymTagUsingNamespace,
    SymTagVTableShape,
    SymTagVTable,
    SymTagCustom,
    SymTagThunk,
    SymTagCustomType,
    SymTagManagedType,
    SymTagDimension,
    SymTagMax
};
enum CBaseTypeEnum {
   cbtNone,
   cbtVoid,
   cbtBool,
   cbtChar,
   cbtUChar,
   cbtWChar,
   cbtShort,
   cbtUShort,
   cbtInt,
   cbtUInt,
   cbtLong,
   cbtULong,
   cbtLongLong,
   cbtULongLong,
   cbtFloat,
   cbtDouble,
   cbtEnd,
};
struct BaseTypeEntry {
   CBaseTypeEnum type;
   const LPCSTR name;
};


typedef map<DWORD, std::wstring> MODULE_MAP;
class VDbg;
extern VDbg * dbg;

struct BREAK_POINT_INFO
{
	BYTE opcode;
	bool invisible;
};
class VDbg
{
	public:
		VDbg();
		void StartDebugging(LPCWSTR path);
	    void dbgSetEvent();
		void SingleStep();
		void stepOut();
		void RunToLine();
		void showCallStack();
		bool ShowSourceLine(DWORD addr, bool bRaw);
		void SetBreakPointBySourceLine(char * szFileName, int lineNumber, bool bInvisible);
		void addSourceFiles(string strFile);
		void CancelBreakPointBySourceLine(char * szFileName, int lineNumber, bool bInvisible);
		void str_split(string src, string token, vector<string> & vec);
		void setDebugMode(int mode);
		void Print_BP_INFO();
		void Print_Var(string var_string);
		void Print_Mem(DWORD Address, DWORD nSize);
		void Print_LocalVars();
		void Print_GlobalVars();
		bool bSingleStepping();
		int  getSourceFilesNumber();
		string strTrim(string s);
		string  getFullPath(string path);
		PROCESS_INFORMATION  pi;
	private:
		STARTUPINFO          si;
		DEBUG_EVENT          debug_event;
		DWORD                startAddress;
		IMAGEHLP_LINE64		 * stepin_line_info;
		HANDLE               hHalt;
		DWORD				 stop_addr;

		bool                 bpHitOnce;
		bool                 srcReadOnce;
		int					 debug_mode;

		map<DWORD, BREAK_POINT_INFO>	 BPs;
		map<string, vector<string>>		 source_file_map;
		map<string, MY_SYMBOL_INFO>         symbol_map;
		map<string, MY_SYMBOL_INFO>         local_symbol_map;


		vector<string>		 m_source_lines;
		vector<string>		 enum_files;

		void OnOutputDebugString();
		void OnProcessCreated();
		void OnException();

		void setTrap();
		void setEIP(int difference);
		
		void setBreakPoint(DWORD addr, bool bInvisible);
		void cancelBreakPoint(DWORD addr, bool bInvisible);
		bool detectBreakPoint(DWORD addr);

		DWORD             getAddrBySourceLine(char * szFileName, int lineNumber);
		IMAGEHLP_LINE64 * GetLineInfoByAddr(DWORD addr);

		void   GetDebuggeeContext(CONTEXT *context);
		HANDLE getDebuggeeProcessHandle();
		HANDLE getDebuggeeThreadHandle();

		BOOL   ReadDebuggeeMemory(LPCVOID source, LPVOID lpBuffer, SIZE_T nSize);
		BOOL   WriteDebuggeeMemory(LPVOID target, LPCVOID source, SIZE_T nSize);

		bool   Symbol_Initialize();
		int    isCurrentInstCall(DWORD addr);
		DWORD  peekEIP();
		STACKFRAME64 * VDbg::getCurrStackFrame();
		DWORD  getReturnAddress();

		string GetTypeValue(int typeID, DWORD modBase, BYTE * pData);
		string GetBaseTypeValue(int typeID, DWORD modBase, BYTE * pData);
		string GetPointerTypeValue(int typeID, DWORD modBase, BYTE * pData);
		string GetEnumTypeValue(int typeID, DWORD modBase, BYTE * pData);
		string GetArrayTypeValue(int typeID, DWORD modBase, BYTE * pData);
		string GetUDTTypeValue(int typeID, DWORD modBase, BYTE * pData);
		CBaseTypeEnum GetBaseTypeEnumID(int typeID, DWORD modBase);
		
		string GetTypeName(int typeID, DWORD modBase);
		string GetBaseTypeName(int typeID, DWORD modBase);
		string GetPointerTypeName(int typeID, DWORD modBase);
		string GetArrayTypeName(int typeID, DWORD modBase);
		string GetEnumTypeName(int typeID, DWORD modBase);
		string GetNameableTypeName(int typeID, DWORD modBase);
		string GetUDTTypeName(int typeID, DWORD modbase);
		string GetFunctionTypeName(int typeID, DWORD modBase);

		bool VariantEqual(VARIANT var, CBaseTypeEnum cBaseType, BYTE* pData);
		BOOL GetDataMemberInfo(DWORD memberID, DWORD modBase, BYTE* pData, ostringstream & valueBuilder);
		BOOL IsSimpleType(DWORD typeID, DWORD modBase);
		BYTE *  CopyDebuggeeMemoryToDebugger(BYTE * pData, DWORD Size);


		int  find_first_occurence(string src, string target);
		void PrintHex(unsigned int value, int width, bool bHexPrefix);
		char ConvertToSafeChar(char ch);
		wchar_t ConvertToSafeWChar(wchar_t ch);
		void  ShowVdbg();
};

inline BOOL __stdcall EnumSourceFilesProc(PSOURCEFILE pSourceFile, PVOID UserContext)
{
	string temp(pSourceFile->FileName);
	dbg->addSourceFiles(temp);
	return true;
}
#endif
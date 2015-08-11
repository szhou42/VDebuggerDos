#include "VDbg.h"


DWORD WINAPI DebugThread(LPVOID lpParamter);
void         help();
VDbg * dbg = NULL;
wchar_t * path = NULL;
int main(int argc, char * argv[])
{
	
	if(argc != 2)
	{
		cout << "invalid parameters" << endl;
		return -1;
	}
	cout << "vdbg (VDBG) 1.0" << endl;
	cout << "For help, type help" << endl;

	HANDLE hThread;
    string command;
	bool bStarted = false;;

	dbg = new VDbg();

	DWORD dwNum = MultiByteToWideChar (CP_ACP, 0, argv[1], -1, NULL, 0);
	path = new wchar_t[dwNum];
	MultiByteToWideChar (CP_ACP, 0, argv[1], -1, path, dwNum);
	
	hThread = CreateThread(NULL, 0, DebugThread, NULL, 0, NULL);
	
	while(true)
	{
		getline(cin, command);
		if(command.substr(0,3) == "run")
		{
			dbg->dbgSetEvent();
			bStarted = true;
		}
		else if(command.substr(0,5) == "break")
		{
			vector<string> vec;
			string break_info = command.substr(6, command.size() - 5);
			dbg->str_split(dbg->strTrim(break_info), ":", vec);
			if(vec.size() != 2)
			{
				cout << "invalid command" <<endl;
				continue;
			}
			string full_path = dbg->getFullPath(vec[0]);
			if(full_path != "")
				dbg->SetBreakPointBySourceLine((char*)full_path.c_str(), atoi(vec[1].c_str()), false);
			else
				cout << "invalid filename"<<endl;
		}
		else if(command.substr(0,2) == "rm")
		{
			vector<string> vec;
			string break_info = command.substr(3, command.size() - 2);
			dbg->str_split(dbg->strTrim(break_info), ":", vec);
			if(vec.size() != 2)
			{
				cout << "invalid command" <<endl;
				continue;
			}
			string full_path = dbg->getFullPath(vec[0]);
			if(full_path != "")
				dbg->CancelBreakPointBySourceLine((char*)full_path.c_str(), atoi(vec[1].c_str()), false);
			else
				cout << "invalid filename"<<endl;
		}
		else if(command.substr(0,5) == "print")
		{
			string var_string = command.substr(6, command.size() - 5);
			dbg->Print_Var(dbg->strTrim(var_string));
		}
		else if(command == "bpinfo")
		{
			dbg->Print_BP_INFO();
		}
		else if(command == "stack")
		{
			dbg->showCallStack();
		}
		else if(command == "locals")
		{
			dbg->Print_LocalVars();
		}
		else if(command == "globals")
		{
			dbg->Print_GlobalVars();
		}
		else if(command == "help")
		{
			help();
		}
		else if(command == "quit")
		{
			CloseHandle(hThread);
			return 0;
		}
		else if(!bStarted)
		{
			cout << "you're not allowed to do anything before you run the program :) :) :)" << endl;
			cout << "<vdbg> ";
			continue;
		}
		else if(command == "cont")
		{
			dbg->dbgSetEvent();
		}
		/*
		else if(command == "runto")
		{
			vector<string> vec;
			string break_info = command.substr(6, command.size() - 5);
			dbg->str_split(dbg->strTrim(break_info), ":", vec);
			if(vec.size() != 2)
			{
				cout << "invalid command" <<endl;
				continue;
			}
			string full_path = dbg->getFullPath(vec[0]);
			if(full_path != "")
				dbg->SetBreakPointBySourceLine((char*)full_path.c_str(), atoi(vec[1].c_str()), true);
			else
				cout << "invalid filename"<<endl;
			dbg->dbgSetEvent();
		}
		*/
		else if(command == "step")
		{
			dbg->setDebugMode(STEP_OVER);
			dbg->dbgSetEvent();
		}
		else if(command == "stepo")
		{
			dbg->stepOut();
		}
		else if(command == "stepi")
		{
			dbg->setDebugMode(STEP_IN);
			dbg->dbgSetEvent();
		}
		else if(command.substr(0,6) == "memory")
		{
			int HexSize, HexAddr;
			string mem_info = command.substr(7, command.size() - 6);
			vector<string> vec;
			dbg->str_split(dbg->strTrim(mem_info), ":", vec);
			if(vec.size() != 2)
			{
				cout << "invalid command" <<endl;
				continue;
			}
			HexSize = strtoul(vec[1].c_str(), NULL, 16);
			HexAddr = strtoul(vec[0].c_str(), NULL, 16);
			dbg->Print_Mem((DWORD)HexAddr,(DWORD)HexSize);
		}
		// else if()
		// ...
		// a lot of else if statements

	}
	//CloseHandle(hThread);	 we do this only before process terminates
	return 0;
}

DWORD WINAPI DebugThread(LPVOID lpParamter)
{
	 dbg->StartDebugging(path);
	 cout<<"debugger thread ends"<<endl;
	 return 0;
}


void help()
{
	cout << "command usage" << endl;
	cout << "1.  run (run the program, will stop when a break point is hit)" << endl;
	cout << "2.  cont (continue the program, will stop when a break point is hit)" << endl;
	cout << "3.  step (step over)" << endl;
	cout << "4.  stepi (step into)" << endl;
	cout << "5.  stepo (step out)" << endl;
	cout << "6.  break \t[file]:[line number] (set break point)" << endl;
	cout << "7.  rm    \t[file]:[line number] (remove break point)" << endl;
	cout << "8.  bpinfo (show current break point information)" << endl;
	cout << "9   stack (show stack information)" << endl;
	cout << "10. print \t[variable]" << endl;
	cout << "11. locals (show all local variables)" << endl;
	cout << "12. globals (show all global variables)" << endl;
	cout << "13. quit" << endl;
	cout << "<vdbg> ";;
}


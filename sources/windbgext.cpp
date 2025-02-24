#include "stdafx.h"

#include <algorithm>
#include <sstream>
#include <string>
#include <fstream>
#include <iomanip> 
#include <regex>

#include <DbgEng.h>

#include "dbgout.h"
#include "arglist.h"
#include "pyinterpret.h"
#include "pyapi.h"
#include "pyclass.h"
#include "version.h"

//////////////////////////////////////////////////////////////////////////////

static int  defaultMajorVersion = -1;
static int  defaultMinorVersion = -1;

//////////////////////////////////////////////////////////////////////////////

void handleException();
std::string getScriptFileName(const std::string &scriptName);
void getPythonVersion(int&  majorVersion, int& minorVersion);
void getDefaultPythonVersion(int& majorVersion, int& minorVersion);
void printString(PDEBUG_CLIENT client, ULONG mask, const char* str);

//////////////////////////////////////////////////////////////////////////////

class InterruptWatch
{
public:

    InterruptWatch(PDEBUG_CLIENT client)
    {
        m_control = client;
        m_stopEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
        m_thread = CreateThread(NULL, 0, threadRoutine, this, 0, NULL);
    }

    ~InterruptWatch()
    {
        SetEvent(m_stopEvent);
        WaitForSingleObject(m_thread, INFINITE);
        CloseHandle(m_stopEvent);
        CloseHandle(m_thread);
    }

    static int quit(void *context)
    {
        HANDLE   quitEvent = (HANDLE)context;
        PyErr_SetString(PyExc_SystemExit(), "CTRL+BREAK");
        SetEvent(quitEvent);
        return -1;
    }

private:

    static DWORD WINAPI threadRoutine(LPVOID lpParameter) {
        return  static_cast<InterruptWatch*>(lpParameter)->interruptWatchRoutine();
    }

    DWORD InterruptWatch::interruptWatchRoutine()
    {
        while (WAIT_TIMEOUT == WaitForSingleObject(m_stopEvent, 250))
        {
            HRESULT  hres = m_control->GetInterrupt();
            if (hres == S_OK)
            {
                HANDLE  quitEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
                PyGILState_STATE state = PyGILState_Ensure();
                Py_AddPendingCall(&quit, (void*)quitEvent);
                PyGILState_Release(state);
                WaitForSingleObject(quitEvent, INFINITE);
                CloseHandle(quitEvent);
            }
        }

        return 0;
    }

    HANDLE  m_thread;

    HANDLE  m_stopEvent;

    CComQIPtr<IDebugControl>  m_control;
};

//////////////////////////////////////////////////////////////////////////////

extern "C"
HRESULT
CALLBACK
DebugExtensionInitialize(
    PULONG  Version,
    PULONG  Flags
)
{
    getDefaultPythonVersion(defaultMajorVersion, defaultMinorVersion);
    return S_OK;
}

//////////////////////////////////////////////////////////////////////////////

extern "C"
VOID
CALLBACK
DebugExtensionUninitialize()
{
   stopAllInterpreter();
}

//////////////////////////////////////////////////////////////////////////////

std::string make_version(int major, int minor)
{
    std::stringstream sstr;
    sstr << std::dec << major << '.' << minor; 

#ifdef _WIN64

    sstr << " x86-64";

#else

    sstr << " x86-32";

#endif

    return sstr.str();
}

extern "C"
HRESULT
CALLBACK
info(
    PDEBUG_CLIENT client,
    PCSTR args
)
{
    try 
    {
        std::stringstream   sstr;

        sstr <<std::endl << "pykd bootstrapper version: " << PYKDEXT_VERSION_MAJOR << '.' << PYKDEXT_VERSION_MINOR << '.' 
            << PYKDEXT_VERSION_SUBVERSION << '.' << PYKDEXT_VERSION_BUILDNO << std::endl;

        std::list<InterpreterDesc>   interpreterList = getInstalledInterpreter();

        int defaultMajor;
        int defaultMinor;

        getDefaultPythonVersion(defaultMajor, defaultMinor);

        sstr << std::endl << "Installed python:" << std::endl << std::endl;
        sstr << std::setw(16) << std::left << "Version:" << std::setw(12) << std::left << "Status: " << std::left << "Image:" <<  std::endl;
        sstr << "------------------------------------------------------------------------------" << std::endl;
        if (interpreterList.size() > 0)
        {
            for (const InterpreterDesc& desc : interpreterList)
            {
                if ( defaultMajor == desc.majorVersion && defaultMinor == desc.minorVersion)
                    sstr << "* ";
                else
                    sstr << "  ";

                sstr << std::setw(14) << std::left << make_version(desc.majorVersion, desc.minorVersion);
            
                sstr << std::setw(12) << std::left << (isInterpreterLoaded(desc.majorVersion, desc.minorVersion) ? "Loaded" : "Unloaded");

                sstr << desc.imagePath << std::endl;
            }
        }
        else
        {
            sstr << "No python interpreter found" << std::endl; 
        }

        sstr << std::endl;

        printString(client, DEBUG_OUTPUT_NORMAL, sstr.str().c_str() );
    } 
    catch(std::exception &e)
    {
        printString(client, DEBUG_OUTPUT_ERROR, e.what() );
    }

    return S_OK;
}

//////////////////////////////////////////////////////////////////////////////

extern "C"
HRESULT
CALLBACK
selectVersion(
    PDEBUG_CLIENT client,
    PCSTR args
)
{
    try
    {
        Options  opts(args);

        int  majorVersion = opts.pyMajorVersion;
        int  minorVersion = opts.pyMinorVersion;

        if (!opts.args.empty())
        {
            std::stringstream sstr;
            sstr << "Unrecognized version string: \"";
            for (std::vector<std::string>::iterator it = opts.args.begin(); it != opts.args.end(); ++it)
            {
                sstr << *it << " ";
            }
            sstr << "\". Expect \"!select -major.minor\"";
            printString(client, DEBUG_OUTPUT_NORMAL, sstr.str().c_str() );
        }

        getPythonVersion(majorVersion, minorVersion);

        if ( opts.pyMajorVersion == majorVersion && opts.pyMinorVersion == minorVersion )
        {
            defaultMajorVersion = majorVersion;
            defaultMinorVersion = minorVersion;
        }
        {
            std::stringstream sstr;
            sstr << "Active Python Interpreter: " << defaultMajorVersion << "." << defaultMinorVersion;
            printString(client, DEBUG_OUTPUT_NORMAL, sstr.str().c_str());
        }

    }
    catch (std::exception &e)
    {
        printString(client, DEBUG_OUTPUT_ERROR, e.what());
    }

    return S_OK;
}

//////////////////////////////////////////////////////////////////////////////

static const char  printUsageMsg[] =
    "\n"
    "usage:\n"
    "\n"
    "!help\n"
    "\tprint this text\n"
    "\n"
    "!info\n"
    "\tlist installed python interpreters\n"
    "\n"
    "!select version\n"
    "\tchange default version of a python interpreter\n"
    "\n"
    "!py [version] [options] [file]\n"
    "\trun python script or REPL\n"
    "\n"
    "\tVersion:\n"
    "\t-2           : use Python2\n"
    "\t-2.x         : use Python2.x\n"
    "\t-3           : use Python3\n"
    "\t-3.x         : use Python3.x\n"
    "\n"
    "\tOptions:\n"
    "\t-g --global  : run code in the common namespace\n"
    "\t-l --local   : run code in the isolated namespace\n"
    "\t-m --module  : run module as the __main__ module ( see the python command line option -m )\n"
    "\n"
    "\tcommand samples:\n"
    "\t\"!py\"                          : run REPL\n"
    "\t\"!py --local\"                  : run REPL in the isolated namespace\n"
    "\t\"!py -g script.py 10 \"string\"\" : run a script file with an argument in the commom namespace\n"
    "\t\"!py -m module_name\" : run a named module as the __main__\n"
    "\n"
    "!pip [version] [args]\n"
    "\trun pip package manager\n"
    "\n"
    "\tVersion:\n"
    "\t-2           : use Python2\n"
    "\t-2.x         : use Python2.x\n"
    "\t-3           : use Python3\n"
    "\t-3.x         : use Python3.x\n"
    "\n"
    "\tpip command samples:\n"
    "\t\"pip list\"                   : show all installed packagies\n"
    "\t\"pip install pykd\"           : install pykd\n"
    "\t\"pip install --upgrade pykd\" : upgrade pykd to the latest version\n"
    "\t\"pip show pykd\"              : show info about pykd package\n"
    ;


//////////////////////////////////////////////////////////////////////////////

extern "C"
HRESULT
CALLBACK
help(
    PDEBUG_CLIENT client,
    PCSTR args
    )
{
    CComQIPtr<IDebugControl>  control = client;

    control->ControlledOutput(
        DEBUG_OUTCTL_AMBIENT_TEXT,
        DEBUG_OUTPUT_NORMAL,
        "%s",
        printUsageMsg
        );

    return S_OK;
}

//////////////////////////////////////////////////////////////////////////////

bool isClassicWindbg()
{
    std::vector<wchar_t>  exebuffer(0x10000);
    auto  exePathLength = GetModuleFileName(NULL, exebuffer.data(), static_cast<DWORD>(exebuffer.size()));

    std::wstring  exepath{ exebuffer.data(), exePathLength };
    const std::wstring  windbgexe{ L"windbg.exe" };

    return (exepath.size() >= windbgexe.size()) && (exepath.rfind(windbgexe) == exepath.size() - windbgexe.size());
}

//////////////////////////////////////////////////////////////////////////////


static const std::regex  shebangRe("^#!\\s*python([2,3])(?:\\.(\\d))?$");

static volatile long recursiveGuard = 0L;

#ifndef DEBUG_OUTPUT_STATUS
#define DEBUG_OUTPUT_STATUS            0x00000400
#endif

extern "C"
HRESULT
CALLBACK
py(
    PDEBUG_CLIENT client,
    PCSTR args
)
{
    ULONG   oldMask;
    client->GetOutputMask(&oldMask);
    ULONG mask = oldMask | DEBUG_OUTPUT_STATUS;

    if (isClassicWindbg())
    {
        mask = mask & ~DEBUG_OUTPUT_PROMPT;
    }

    client->SetOutputMask(mask);

    try {

        if ( 1 < ++recursiveGuard  )
            throw std::exception( "can not run !py command recursive\n");

        Options  opts(args);

        if (opts.showHelp)
            throw std::exception(printUsageMsg);

        int  majorVersion = opts.pyMajorVersion;
        int  minorVersion = opts.pyMinorVersion;

        std::string  scriptFileName;

        if ( opts.args.size() > 0 && !opts.runModule )
        {
            scriptFileName = getScriptFileName(opts.args[0]);
            if ( scriptFileName.empty() )
            {
                const char* msg = "script not found: %s";
                size_t size = std::snprintf(nullptr, 0, msg, opts.args[0].c_str()) + 1;
                std::unique_ptr<char[]> buf(new char[size]);
                std::snprintf(buf.get(), size, msg, opts.args[0].c_str());
                throw std::invalid_argument(std::string(buf.get(), buf.get() + size));
            }
        }

        if ( !opts.runModule && majorVersion == -1 && minorVersion == -1 )
        {
            std::ifstream  scriptFile(scriptFileName);

            if ( scriptFile.is_open() )
            {
                std::string  firstline;
                std::getline(scriptFile, firstline);

                std::smatch  mres;
                if (std::regex_match(firstline, mres, shebangRe))
                {
                    majorVersion = atol(std::string(mres[1].first, mres[1].second).c_str());

                    if (mres[2].matched)
                    {
                        minorVersion = atol(std::string(mres[2].first, mres[2].second).c_str());
                    }
                }
            }
        }

        getPythonVersion(majorVersion, minorVersion);

        AutoInterpreter  autoInterpreter(opts.global, majorVersion, minorVersion);

        PyObjectRef  mainMod = PyImport_ImportModule("__main__");
        PyObjectRef  globals = PyObject_GetAttrString(mainMod, "__dict__");

        PyObjectRef  dbgOut = make_pyobject<DbgOut>(client);
        PySys_SetObject("stdout", dbgOut);

        PyObjectRef  dbgErr = make_pyobject<DbgOut>(client);
        PySys_SetObject("stderr", dbgErr);

        PyObjectRef dbgIn = make_pyobject<DbgIn>(client);
        PySys_SetObject("stdin", dbgIn);

        InterruptWatch  interruptWatch(client);

        PyRun_String("import sys\nsys.setrecursionlimit(500)\n", Py_file_input, globals, globals);

        if (opts.args.empty())
        {
            PyObjectRef  result = PyRun_String("import pykd\nfrom pykd import *\n", Py_file_input, globals, globals);
            PyErr_Clear();
            result = PyRun_String("import code\ncode.InteractiveConsole(globals()).interact()\n", Py_file_input, globals, globals);
        }
        else 
        {
            if (IsPy3())
            {
                std::wstring  scriptFileNameW = _bstr_t(scriptFileName.c_str());

                std::vector<std::wstring>   argws(opts.args.size());

                if ( !scriptFileNameW.empty() )
                    argws[0] = scriptFileNameW;
                else
                    argws[0] = L"";

                for (size_t i = 1; i < opts.args.size(); ++i)
                    argws[i] = _bstr_t(opts.args[i].c_str());

                std::vector<wchar_t*>  pythonArgs(opts.args.size());
                for (size_t i = 0; i < opts.args.size(); ++i)
                    pythonArgs[i] = const_cast<wchar_t*>(argws[i].c_str());

                PySys_SetArgv_Py3((int)opts.args.size(), &pythonArgs[0]);

                if ( opts.runModule )
                {
                   std::stringstream sstr;
                   sstr << "runpy.run_module(\"" << opts.args[0] << "\", run_name='__main__',  alter_sys=True)" << std::endl;

                    PyObjectRef result;
                    result = PyRun_String("import runpy\n", Py_file_input, globals, globals);
                    result = PyRun_String(sstr.str().c_str(), Py_file_input, globals, globals);
                }
                else
                {
                    FILE* fs = NULL;
                    if ((minorVersion >= 5) && (minorVersion <= 13)) {
                        PyObjectRef pyfile = PyUnicode_FromString(scriptFileName.c_str());
                        fs = _Py_fopen_obj(pyfile, "r");
                    } else {
                        throw std::invalid_argument("Unsupported C API _Py_fopen_obj\n");
                    }

                    if ( !fs )
                        throw std::invalid_argument("Unable to open script\n");
                    
                      PyObjectRef result = PyRun_FileExFlags(fs, scriptFileName.c_str(), Py_file_input, globals, globals, 1, NULL);
                }
            }
            else
            {
                std::vector<char*>  pythonArgs(opts.args.size());

                if ( !scriptFileName.empty() )
                    pythonArgs[0] = const_cast<char*>(scriptFileName.c_str());
                else
                    pythonArgs[0] = "";

                for (size_t i = 1; i < opts.args.size(); ++i)
                    pythonArgs[i] = const_cast<char*>(opts.args[i].c_str());

                PySys_SetArgv((int)opts.args.size(), &pythonArgs[0]);

                if ( opts.runModule )
                {
                   std::stringstream sstr;
                   sstr << "runpy.run_module('" << opts.args[0] << "', run_name='__main__', alter_sys=True)" << std::endl;

                    PyObjectRef result;
                    result = PyRun_String("import runpy\n", Py_file_input, globals, globals);
                    result = PyRun_String(sstr.str().c_str(), Py_file_input, globals, globals);
                }
                else
                {
                    PyObjectRef  pyfile = PyFile_FromString(const_cast<char*>(scriptFileName.c_str()), "r");
                    if (!pyfile)
                        throw std::invalid_argument("script not found\n");

                    FILE *fs = PyFile_AsFile(pyfile);

                    PyObjectRef result = PyRun_File(fs, scriptFileName.c_str(), Py_file_input, globals, globals);
                }
            }
        }

        handleException();

        if ( !opts.global )
            PyDict_Clear(globals);
    }
    catch (std::exception &e)
    {
        printString(client, DEBUG_OUTPUT_ERROR, e.what() );
    }

    client->SetOutputMask(oldMask);

    --recursiveGuard;

    return S_OK;
}

//////////////////////////////////////////////////////////////////////////////

extern "C"
HRESULT
CALLBACK
pip(
    PDEBUG_CLIENT client,
    PCSTR args
)
{

    try {

        if ( 1 < ++recursiveGuard  )
            throw std::exception( "can not run !pip command recursive\n");

        Options  opts(args);

        int  majorVersion = opts.pyMajorVersion;
        int  minorVersion = opts.pyMinorVersion;

        getPythonVersion(majorVersion, minorVersion);

        AutoInterpreter  autoInterpreter(true, majorVersion, minorVersion);

        PyObjectRef  dbgOut = make_pyobject<DbgOut>(client);
        PySys_SetObject("stdout", dbgOut);

        PyObjectRef  dbgErr = make_pyobject<DbgOut>(client);
        PySys_SetObject("stderr", dbgErr);

        PyObjectRef dbgIn = make_pyobject<DbgIn>(client);
        PySys_SetObject("stdin", dbgIn);

        PyObjectRef  mainName = IsPy3() ? PyUnicode_FromString("__main__") : PyString_FromString("__main__");
        PyObjectRef  mainMod = PyImport_Import(mainName);
        PyObjectRef  globals = PyObject_GetAttrString(mainMod, "__dict__");

        if (IsPy3())
        {
            std::vector<std::wstring>   argws(opts.args.size() + 1);

            argws[0] = L"pip";
            
            for (size_t i = 0; i < opts.args.size(); ++i)
                argws[i+1] = _bstr_t(opts.args[i].c_str());

            std::vector<wchar_t*>  pythonArgs(argws.size());
            for (size_t i = 0; i < argws.size(); ++i)
                pythonArgs[i] = const_cast<wchar_t*>(argws[i].c_str());

            PySys_SetArgv_Py3((int)argws.size(), &pythonArgs[0]);

            std::stringstream sstr;
            sstr << "runpy.run_module('pip', run_name='__main__',  alter_sys=True)" << std::endl;

            PyObjectRef result;
            result = PyRun_String("import runpy\n", Py_file_input, globals, globals);
            result = PyRun_String(sstr.str().c_str(), Py_file_input, globals, globals);
        }
        else
        {
            std::vector<char*>  pythonArgs(opts.args.size() + 1);

            pythonArgs[0] = "pip";

            for (size_t i = 0; i < opts.args.size(); ++i)
                pythonArgs[i+1] = const_cast<char*>(opts.args[i].c_str());

            PySys_SetArgv((int)pythonArgs.size(), &pythonArgs[0]);

            std::stringstream sstr;
            sstr << "runpy.run_module('pip', run_name='__main__', alter_sys=True)" << std::endl;

            PyObjectRef result;
            result = PyRun_String("import runpy\n", Py_file_input, globals, globals);
            result = PyRun_String(sstr.str().c_str(), Py_file_input, globals, globals);
        }

        handleException();
    }
    catch (std::exception &e)
    {
         printString(client, DEBUG_OUTPUT_ERROR, e.what() );
    }

    --recursiveGuard;

    return S_OK;
}

//////////////////////////////////////////////////////////////////////////////

void handleException()
{
    PyObjectRef  errtype, errvalue, traceback;

    PyErr_Fetch(&errtype, &errvalue, &traceback);

    PyErr_NormalizeException(&errtype, &errvalue, &traceback);

    if (errtype && errtype != PyExc_SystemExit())
    {
        PyObjectRef  traceback_module = PyImport_ImportModule("traceback");

        std::stringstream  sstr;

        PyObjectRef  format_exception = PyObject_GetAttrString(traceback_module, "format_exception");

        PyObjectRef  args = PyTuple_New(3);

        PyObject*  arg0 = errtype ? static_cast<PyObject*>(errtype) : Py_None(); Py_IncRef(arg0);
        PyObject*  arg1 = errvalue ? static_cast<PyObject*>(errvalue) : Py_None(); Py_IncRef(arg1);
        PyObject*  arg2 = traceback ? static_cast<PyObject*>(traceback) : Py_None(); Py_IncRef(arg2);
        
        PyTuple_SetItem(args, 0, arg0);
        PyTuple_SetItem(args, 1, arg1);
        PyTuple_SetItem(args, 2, arg2);

        PyObjectRef  lst = PyObject_Call(format_exception, args, NULL);

        sstr << std::endl << std::endl;

        for (size_t i = 0; i < PyList_Size(lst); ++i)
        {
            PyObjectBorrowedRef  item = PyList_GetItem(lst, i);
            sstr << std::string(convert_from_python(item)) << std::endl;
        }

        throw std::exception(sstr.str().c_str());
    }
}

///////////////////////////////////////////////////////////////////////////////

void getPathList( std::list<std::string>  &pathStringLst)
{
    PyObjectBorrowedRef  pathLst = PySys_GetObject("path");

    size_t  pathLstSize = PyList_Size(pathLst);

    for (size_t i = 0; i < pathLstSize; i++)
    {
        PyObjectBorrowedRef  pathLstItem = PyList_GetItem(pathLst, i);

        if ( IsPy3() )
        {
            std::vector<wchar_t>  buf(0x10000);
            size_t  len = buf.size();
            PyUnicode_AsWideChar(pathLstItem, &buf[0], len);

            DWORD  attr =  GetFileAttributesW(&buf[0]);
            if ( attr == INVALID_FILE_ATTRIBUTES || (attr & FILE_ATTRIBUTE_DIRECTORY ) == 0 )
                continue;

            pathStringLst.push_back( std::string(_bstr_t(&buf[0])));
        }
        else
        {
            char*  path = PyString_AsString(pathLstItem);

            DWORD  attr =  GetFileAttributesA(path);
            if ( attr == INVALID_FILE_ATTRIBUTES || (attr & FILE_ATTRIBUTE_DIRECTORY ) == 0 )
                continue;

            pathStringLst.push_back(path);
        }
    }
}

///////////////////////////////////////////////////////////////////////////////

std::string getScriptFileName(const std::string &scriptName)
{
    char*  ext = ".py";

    DWORD searchResult = SearchPathA(
        NULL,
        scriptName.c_str(),
        ext,
        0,
        NULL,
        NULL);

    if ( searchResult == 0 )
    {
        return "";
    }

    size_t pos = 0;
    while ((pos = scriptName.find(std::string("\\\\"), pos)) != std::string::npos) {
        ++searchResult;
        pos += std::string("\\\\").length();
    }

    std::vector<char>  pathBuffer(searchResult);

    searchResult = 
        SearchPathA(
            NULL,
            scriptName.c_str(),
            ext,
            static_cast<DWORD>(pathBuffer.size()),
            &pathBuffer.front(),
            NULL );

    return std::string(&pathBuffer.front());
}

///////////////////////////////////////////////////////////////////////////////

void getPythonVersion(int&  majorVersion, int& minorVersion)
{
    if (majorVersion == -1)
        return getDefaultPythonVersion(majorVersion, minorVersion);

    std::list<InterpreterDesc>   interpreterList = getInstalledInterpreter();

    bool  found = false;
    bool  anyMinorVersion = minorVersion == -1;

    for (auto interpret : interpreterList)
    {
        if (majorVersion == interpret.majorVersion && 
            (anyMinorVersion ? (minorVersion < interpret.minorVersion) : (minorVersion == interpret.minorVersion)) )
        {
            minorVersion = interpret.minorVersion;
            found = true;
        }
    }

    if (!found)
        throw std::exception("failed to find python interpreter\n");
}

///////////////////////////////////////////////////////////////////////////////

void getDefaultPythonVersion(int& majorVersion, int& minorVersion)
{
    std::list<InterpreterDesc>   interpreterList = getInstalledInterpreter();

    bool  found = false;
    majorVersion = -1;
    minorVersion = -1;
    
    for (auto interpret : interpreterList)
    {
        if (defaultMajorVersion == interpret.majorVersion && defaultMinorVersion == interpret.minorVersion)
        {
            majorVersion = defaultMajorVersion;
            minorVersion = defaultMinorVersion;
            return;
        }
    }

    for (auto interpret : interpreterList)
    {
        if (3 == interpret.majorVersion &&  minorVersion <= interpret.minorVersion )
        {
            found = true;
            majorVersion = interpret.majorVersion;
            minorVersion = interpret.minorVersion;
        }
    }

    if (found)
        return;

    for (auto interpret : interpreterList)
    {
        if (2 == interpret.majorVersion && minorVersion <= interpret.minorVersion )
        {
            found = true;
            majorVersion = interpret.majorVersion;
            minorVersion = interpret.minorVersion;
        }
    }

    if (found)
        return;

    if (!found)
        throw std::exception("failed to find python interpreter\n");
}

///////////////////////////////////////////////////////////////////////////////

void printString(PDEBUG_CLIENT client, ULONG mask, const char* str)
{
    CComQIPtr<IDebugControl>  control = client;

    ULONG  engOpts;
    bool prefer_dml = SUCCEEDED(control->GetEngineOptions(&engOpts)) && ( (engOpts & DEBUG_ENGOPT_PREFER_DML ) != 0 );

    std::stringstream  sstr(str);
    while( sstr.good() )
    {
        std::string  line;
        std::getline(sstr, line);

        if (isClassicWindbg() && prefer_dml && mask == DEBUG_OUTPUT_ERROR )
        {
            line = std::regex_replace(line, std::regex("&"), "&amp;");
            line = std::regex_replace(line, std::regex("<"), "&lt;");
            line = std::regex_replace(line, std::regex(">"), "&gt;");

            control->ControlledOutput(
                DEBUG_OUTCTL_AMBIENT_DML,
                mask,
                "<col fg=\"errfg\" bg=\"errbg\">%s</col>\n",
                line.c_str()
                );
        }
        else
        {
            control->ControlledOutput(
                DEBUG_OUTCTL_AMBIENT_TEXT,
                mask,
                "%s\n",
                line.c_str()
                );
        }
    }

}

///////////////////////////////////////////////////////////////////////////////

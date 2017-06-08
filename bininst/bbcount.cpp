#include <pin.H>
#include <stdio.h>
#include <iostream>
#include <vector>
#include <map>
#include <sstream>
#include <unistd.h>


using namespace std;

KNOB<string> KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool",
    "o", "bbcount.out", "specify output file name");
KNOB<UINT32> KnobLibC(KNOB_MODE_WRITEONCE, "pintool",
    "libc", "0", "if you want to monitor libc BB");
KNOB<UINT32> KnobTimeout(KNOB_MODE_WRITEONCE, "pintool",
    "x", "10000", "specify timeout in miliseconds");
KNOB<string> KnobXLibraries(KNOB_MODE_WRITEONCE, "pintool",
    "l", "", "specify shared libraries to be monitored, separated by commas");


static vector<pair<ADDRINT,ADDRINT> > allAddr;
static map<ADDRINT, unsigned int> bbcount;
static vector<string> libNames;
static FILE * traceFile;


VOID PIN_FAST_ANALYSIS_CALL rememberBlock(ADDRINT bbl)
{
  bbcount[bbl] = bbcount[bbl] + 1;
}


BOOL isMonitoredAddress(ADDRINT bb)
{
    for(vector<pair<ADDRINT,ADDRINT> >::iterator it = allAddr.begin(); it != allAddr.end(); ++it) {
        if ((bb >= (*it).first) && (bb <= (*it).second))
        return true;
    }
    return false;
}


VOID traceFn(TRACE trace, VOID *v)
{
    for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl)) {
        if (isMonitoredAddress(BBL_Address(bbl))) {
            BBL_InsertCall(bbl, IPOINT_ANYWHERE,
                           AFUNPTR(rememberBlock), IARG_FAST_ANALYSIS_CALL,
                           IARG_ADDRINT, BBL_Address(bbl), IARG_END);
        }
    }
}


VOID imageLoadFn(IMG img, VOID *v)
{
    if (IMG_IsMainExecutable(img)) {
        #ifdef DEBUG
        printf("image map main %p - %p\n", (void*) IMG_LowAddress(img), (void*) IMG_HighAddress(img));
        #endif
        allAddr.push_back(std::make_pair(IMG_LowAddress(img), IMG_HighAddress(img)));
    } else {
        if (KnobLibC.Value() > 0 && IMG_Name(img).find("libc.") != std::string::npos)
            allAddr.push_back(std::make_pair(IMG_LowAddress(img), IMG_HighAddress(img)));

        for (vector<string>::iterator it=libNames.begin();it !=libNames.end();++it) {
            if (IMG_Name(img).find(*it)!=std::string::npos)
                allAddr.push_back(std::make_pair(IMG_LowAddress(img), IMG_HighAddress(img)));
        }
    }
}


static VOID timeoutFn(VOID * arg)
{
    sleep(KnobTimeout.Value());
    PIN_ExitApplication(0);
    PIN_ExitThread(0);
}


VOID finiFn(INT32 code, VOID *v)
{
    map<ADDRINT,unsigned int>::iterator bb;
    for (bb=bbcount.begin(); bb != bbcount.end(); ++bb) {
        fprintf(traceFile, "%p %u\n", (void *) bb->first, bb->second);
    }

    fclose(traceFile);
}


INT32 usage()
{
    cerr << "This tool counts the number of basic block executed with their frequencies" << endl;
    cerr << endl << KNOB_BASE::StringKnobSummary() << endl;
    return -1;
}


int main(int argc, char * argv[])
{
    PIN_InitSymbols();

    if (PIN_Init(argc, argv)) return usage();

    traceFile = fopen(KnobOutputFile.Value().c_str(), "w");
    if (!traceFile) {
        cerr << "Error opening output file..." << endl;
        return -1;
    }

    if (!KnobXLibraries.Value().empty()) {
        stringstream libs(KnobXLibraries.Value().c_str());
        while(libs.good()) {
            string temp;
            getline(libs, temp, ',');
            libNames.push_back(temp);
        }
    }

    IMG_AddInstrumentFunction(imageLoadFn, 0);

    TRACE_AddInstrumentFunction(traceFn, 0);

    PIN_AddFiniFunction(finiFn, 0);

    PIN_THREAD_UID threadUid;
    if (KnobTimeout.Value() > 0)
    	PIN_SpawnInternalThread(timeoutFn, 0, 0, &threadUid);

    PIN_StartProgram();
}


#include <windows.h>
#include <iostream>
#include <thread>

typedef int (*LoadFunc)();
typedef int (*GetEventFunc)(void* dest);


HINSTANCE hDll = NULL;

void
ListenThread(){
    LoadFunc startEventListener = (LoadFunc)GetProcAddress(hDll, "StartEventListener");
    if (startEventListener == NULL) {
        std::cerr << "Could not locate the function StartEventListener" << std::endl;
        FreeLibrary(hDll);
        return ;
    }

    // Call the function
    int result = startEventListener();
    return;

}


int
main()
{
    // Load the DLL
    hDll = LoadLibraryW(L"C:\\git\\ebpf-for-windows\\x64\\Debug\\process_monitor_dll.dll");
    if (hDll == NULL) {
        std::cerr << "Could not load the DLL" << std::endl;
        return 1;
    }

    std::thread th(ListenThread);
    th.detach();
    Sleep(1000);


   GetEventFunc getEventFunc = (GetEventFunc)GetProcAddress(hDll, "GetEvent");

    while (1){
        char c[2048];
        getEventFunc(c);

        printf("\n%d\n", c[0]);

    }
    
    // Free the DLL
    FreeLibrary(hDll);

    return 0;
}

#include <windows.h>
#include <iostream>
#include "DataTypes.h"
#include <queue>
#include <mutex>


std::queue<msg_execve_event> eventQueue;
std::mutex queueMutex_;

int
EnqueEvent(process_info_t* process_info, wchar_t* path)
{
    msg_execve_event event{};
    event.common.op = 5;
    event.parent.pid = process_info->creating_process_id;
    event.process.pid = process_info->process_id ;
    //ToD: Fix tid of main thread of new process
    event.process.tid = process_info->process_id ;
    event.process.flags = 1;
    event.process.nspid = 0;
    event.process.size = offsetof(struct msg_process, args);
    wcstombs(event.process.args, path, MAX_PATH);
    event.process.size += (uint32_t)strlen(event.process.args);
    event.process.ktime = process_info->creation_time;
    std::scoped_lock lock(queueMutex_);
    if (eventQueue.size() < 100) {
        eventQueue.push(event);
    }
    return 1;
}


extern "C" __declspec(dllexport) int
GetEvent(void* dest)
{
    while (1) {
        msg_execve_event event{};
        bool bNoEvents = false;
        {
            std::scoped_lock lock(queueMutex_);
            if (!eventQueue.size()) {
                bNoEvents = true;
            } else {
                event = eventQueue.front();
                eventQueue.pop();
                bNoEvents = false;
            }
        }
        if (bNoEvents) {
            Sleep(100);
            continue;
        } else if (event.common.op) {
            memcpy(dest, &event, sizeof(msg_execve_event));
            return 1;
        }
    }
}

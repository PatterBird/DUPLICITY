#include "queue.h"
#include "winbox.h"
#include <queue>
#include <mutex>
#include <condition_variable>

static std::queue<DetectionResult> alertQueue;
static std::queue<TaskSchResult> taskAlertQueue;
static std::mutex alertMutex;
static std::condition_variable alertCV;
static bool alertRunning = true;


void queueAlert(const DetectionResult& result){
    std::lock_guard<std::mutex> lock(alertMutex);
    if (!result.details.empty()){ alertQueue.push(result); }

    if (!alertRunning) { return; }

    alertCV.notify_one();
}

void queueAlert(const TaskSchResult& result) {
    {
        std::lock_guard<std::mutex> lock(alertMutex);
        if (!alertRunning || !result.suspicious) { return; }
        taskAlertQueue.push(result);
    }
    alertCV.notify_one();
}


void alertWorker(){
    while (true) {
        DetectionResult result{};
        TaskSchResult taskResult{};
        bool isTask = false;

        {
            std::unique_lock<std::mutex> lock(alertMutex);

            // Sleep until an alert is available
            alertCV.wait(lock, [] {return !alertQueue.empty() || !taskAlertQueue.empty() || !alertRunning; });

            if (!alertRunning && alertQueue.empty() && taskAlertQueue.empty()) { break; }
            if (!alertQueue.empty()) {
                result = alertQueue.front();
                alertQueue.pop();
            }
            else if (!taskAlertQueue.empty()) {
                taskResult = taskAlertQueue.front();
                taskAlertQueue.pop();
                isTask = true;
            }
        }
        if (isTask) {
            taskAlert(taskResult);
        }
        else {
            popREGAlert(result);
        }
    }
}

void haltAlertWorker(){
    {
        std::lock_guard<std::mutex> lock(alertMutex);
        alertRunning = false;
    }

    alertCV.notify_all();
}
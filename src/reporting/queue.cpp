#include "queue.h"
#include "winbox.h"
#include <queue>
#include <mutex>
#include <condition_variable>

static std::queue<DetectionResult> alertQueue;
static std::mutex alertMutex;
static std::condition_variable alertCV;
static bool alertRunning = true;


void queueAlert(const DetectionResult& result){
    std::lock_guard<std::mutex> lock(alertMutex);
    if (!result.details.empty()){ alertQueue.push(result); }

    if (!alertRunning) { return; }

    alertCV.notify_one();
}


void alertWorker(){
    while (true){
        DetectionResult result;

        {
            std::unique_lock<std::mutex> lock(alertMutex);

            // Sleep until an alert is available
            alertCV.wait(lock, [] {return !alertQueue.empty() || !alertRunning;});

            if (!alertRunning) { break; }

            result = alertQueue.front();
            alertQueue.pop();
        }
        popREGAlert(result);
    }
}

void haltAlertWorker(){
    {
        std::lock_guard<std::mutex> lock(alertMutex);
        alertRunning = false;
    }

    alertCV.notify_all();
}
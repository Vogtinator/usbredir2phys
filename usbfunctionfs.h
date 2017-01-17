#ifndef USBFunctionFS_H
#define USBFunctionFS_H

#include <atomic>
#include <functional>
#include <map>
#include <string>
#include <thread>
#include <vector>

struct usb_ctrlrequest;
struct USBConfiguration;
struct USBDevice;

class USBFunctionFS
{
    struct EPData
    {
        EPData() = default;
        EPData(EPData &&) = delete;
        EPData(const EPData &) = delete;
        ~EPData();

        std::thread thread;
        std::atomic_bool waiting_for_answer{false};
        int fd;
    };

    //                         header            data      size
    typedef std::function<void(usb_ctrlrequest&, uint8_t*, size_t)> EP0Callback;
    //                         ep       data      size
    typedef std::function<void(uint8_t, uint8_t*, size_t)> EPXCallback;

public:
    USBFunctionFS() = default;
    USBFunctionFS(const USBFunctionFS &other) = delete;
    USBFunctionFS(USBFunctionFS&& other) = delete;
    ~USBFunctionFS();

    bool create(std::string name);

    bool initForConfig(const USBDevice &dev, const USBConfiguration &config);

    /* For use with select. */
    int getEP0FD();
    bool handleEP0Data();

    /* Use these functions to inhibit reading data from the specified ep. */
    void pauseProcessing(uint8_t ep);
    bool processingPaused(uint8_t ep);
    void resumeProcessing(uint8_t ep);

    /* Use this to access the various endpoints.
     * Only read from IN eps and only write to OUT eps. */
    bool writePacketEP(uint8_t ep, const uint8_t *data, size_t size);
    bool readPacketEP(uint8_t ep, uint8_t *data, size_t size);

    // Only used in handleEP0Data
    EP0Callback ep0_cb;
    // Used in various threads
    // std::atomic<EPXCallback> epx_cb;
    // However, that ^^^ does not work. As it's only written once
    // before the fun/thread starts, it doesn't matter
    EPXCallback epx_cb;

private:
    int openEP(uint8_t id, bool nonblock);

    bool handleEPXData(uint8_t ep, EPData &ep_data);
    void pollEPX(uint8_t ep, uint32_t max_size, EPData &ep_data);

    std::string path;
    int dirfd = -1;
    std::atomic_bool stop_threads{false};
    std::map<uint8_t, std::shared_ptr<EPData>> endpoints;
};

#endif // USBFunctionFS_H

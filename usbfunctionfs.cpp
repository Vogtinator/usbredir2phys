#include "usbfunctionfs.h"

#include <linux/usb/functionfs.h>

#include <fcntl.h>
#include <cstdio>
#include <cstring>
#include <sys/types.h>
#include <unistd.h>

#include "usbdevice.h"

template<typename... Args>
    void debugPrintf(Args... args)
{
    #ifndef NDEBUG
        printf(args...);
    #endif
}

USBFunctionFS::~USBFunctionFS()
{
    if(path.empty())
        return;

    stop_threads = true;

    if(dirfd >= 0)
        close(dirfd);

    // Close all endpoints
    endpoints.clear();

    std::string command = std::string("umount " + path);
    system(command.c_str());

    rmdir(path.c_str());
}

bool USBFunctionFS::create(std::string name)
{
    // Check for invalid name
    if(name.find('\'') != std::string::npos)
        return false;

    char tmpname[] = "/tmp/ffsXXXXXX";
    if(mkdtemp(tmpname) == nullptr)
        return false;

    path = tmpname;

    std::string command = std::string("mount -t functionfs '" + name + "' " + path);
    if(system(command.c_str()) == 0)
    {
        dirfd = open(path.c_str(), O_RDONLY | O_DIRECTORY);
        return dirfd >= 0;
    }

    rmdir(path.c_str());
    path = "";
    return false;
}

int USBFunctionFS::openEP(uint8_t id, bool nonblock)
{
    char name[5];
    snprintf(name, sizeof(name), "ep%x", id);
    return openat(dirfd, name, O_RDWR | (nonblock ? O_NONBLOCK : 0));
}

bool USBFunctionFS::writePacketEP(uint8_t ep, const uint8_t *data, size_t size)
{
    auto &&ep_data = endpoints.find(ep);
    if(ep_data == endpoints.end())
        return false;

    return write(ep_data->second->fd, data, size) == ssize_t(size);
}

bool USBFunctionFS::readPacketEP(uint8_t ep, uint8_t *data, size_t size)
{
    auto &&ep_data = endpoints.find(ep);
    if(ep_data == endpoints.end())
        return false;

    return read(ep_data->second->fd, data, size) == ssize_t(size);
}

bool USBFunctionFS::handleEPXData(uint8_t ep, EPData &ep_data)
{
    while(ep_data.waiting_for_answer)
    {
        using namespace std::chrono_literals;
        std::this_thread::sleep_for(5ms);

        if(stop_threads)
            return true;
    }

    uint8_t buf[USB_MAX_CTRL_SIZE];
    auto r = read(ep_data.fd, buf, sizeof(buf));
    if(r == 0 || (r < 0 && errno == EAGAIN))
        return true; // EOF
    else if(r < 0)
    {
        perror("EPX READ");
        return false;
    }

    debugPrintf("Host: Received EPX Packet(%ld bytes)\n", r);

    epx_cb(ep, buf, r);

    return true;
}

template <typename T>
void appendToVector(std::vector<uint8_t> &v, const T &data)
{
    v.resize(v.size() + sizeof(T));
    memcpy(v.data() + v.size() - sizeof(T), &data, sizeof(T));
}

bool USBFunctionFS::initForConfig(const USBDevice &dev, const USBConfiguration &config)
{
    int ep0 = openEP(0, true);

    if(ep0 == -1)
    {
        fprintf(stderr, "Could not open ep0!");
        return false;
    }

    endpoints[0x80] = std::make_shared<EPData>();
    endpoints[0x80]->fd = ep0;

    std::vector<uint8_t> request;

    /* TODO: Same descriptors used for FS and HS (*2) */
    uint32_t length = sizeof(usb_functionfs_descs_head_v2)
                      + sizeof(uint32_t) * 2
                      + config.full_desc.size() * 2;

    request.reserve(length);

    usb_functionfs_descs_head_v2 head {
        .magic = FUNCTIONFS_DESCRIPTORS_MAGIC_V2,
        .length = length,
        .flags = FUNCTIONFS_HAS_FS_DESC | FUNCTIONFS_HAS_HS_DESC | 64 /* FUNCTIONFS_ALL_CTRL_RECIP */
    };

    appendToVector(request, head);

    /* Count descriptors */
    uint32_t fs_count = 0;
    {
        uint32_t size = config.full_desc.size();
        const uint8_t *data = config.full_desc.data();

        while(size) {
            auto *desc = reinterpret_cast<const usb_descriptor_header*>(data);
            if(desc->bLength < sizeof(usb_descriptor_header) || desc->bLength > size)
                break; /* Invalid bLength */

            fs_count += 1;
            data += desc->bLength;
            size -= desc->bLength;
        }
    }

    if(fs_count == 0)
    {
        fprintf(stderr, "Config %d has no valid descriptors!", config.desc.bConfigurationValue);
        return false;
    }

    appendToVector(request, uint32_t(fs_count));
    appendToVector(request, uint32_t(fs_count));

    request.insert(request.end(), config.full_desc.begin(), config.full_desc.end());
    request.insert(request.end(), config.full_desc.begin(), config.full_desc.end());

    //auto e = write(open("/tmp/ep0descs", O_CREAT | O_WRONLY, 0777), request.data(), request.size());
    auto e = write(ep0, request.data(), request.size());
    if(e != ssize_t(request.size()))
    {
        perror("FFS EP0 descs write (Kernel too old?)");
        return false;
    }

    /* Write string descriptors */
    request.clear();

    /* TODO: Handle all strings and languages here */
    auto s = dev.strings.getUTF8(0x409, config.desc.iConfiguration);

    length = sizeof(usb_functionfs_strings_head)
             + sizeof(uint16_t)
             + s.size();

    usb_functionfs_strings_head shead {
        .magic = FUNCTIONFS_STRINGS_MAGIC,
        .length = length,
        .str_count = 1,
        .lang_count = 1
    };

    appendToVector(request, shead);
    appendToVector(request, uint16_t(0x409));
    request.insert(request.end(), s.c_str(), s.c_str() + s.size());

    //e = write(open("/tmp/ep0strs", O_CREAT | O_WRONLY, 0777), request.data(), request.size());
    e = write(ep0, request.data(), request.size());
    if(e != ssize_t(request.size()))
    {
        perror("FFS EP0 strs write");
        return false;
    }

    /* FFS does not use the EP address, it uses consecutive numbers
     * based on the descriptors we supplied...
     * FFS, FFS! */
    uint8_t index = 0;
    for(auto&& intf : config.interfaces)
        for(auto&& epAddr : intf.endpoints)
        {
            if(endpoints.find(epAddr) != endpoints.end())
            {
                perror("Duplicate EP address?");
                return false;
            }

            auto epfd = openEP(index += 1, false);
            if(epfd == -1)
            {
                perror("FFS EP open");
                return false;
            }

            this->endpoints[epAddr] = std::make_shared<EPData>();
            this->endpoints[epAddr]->fd = epfd;
        }

    for(auto &&ep : endpoints)
    {
        auto &epAddr = ep.first;
        auto &ep_data = *ep.second;

        // ep0 is handled separately
        if(epAddr == 0x80)
            continue;

        if((epAddr & USB_DIR_IN))
            continue;

        /* Create read threads for all OUT endpoints.
         * Normally this could be handled in the main thread,
         * but despite O_NONBLOCK is set it blocks sometimes... */

        /* Although 'this' is captured by value it is still a pointer.
         * However, the threads cannot outlive this object, so it is safe. */
        auto ep_thread = [this, epAddr, &ep_data] ()
        {
            while(!this->stop_threads.load())
                handleEPXData(epAddr, ep_data);
        };

        ep_data.thread = std::thread{ep_thread};
    }

    return true;
}

int USBFunctionFS::getEP0FD()
{
    return endpoints.at(0x80)->fd;
}

bool USBFunctionFS::handleEP0Data()
{
    auto &ep_data = *endpoints[0x80];

    /* Read events until EOF or reponse needed */
    while(!ep_data.waiting_for_answer)
    {
        usb_functionfs_event event;
        auto r = read(ep_data.fd, &event, sizeof(event));
        if(r == 0 || (r < 0 && errno == EAGAIN))
            return true; // EOF
        else if(r < 0)
        {
            perror("EP0 READ");
            return false;
        }
        else if(size_t(r) < sizeof(event))
        {
            perror("EP0 partial read");
            return false;
        }

        /* Handle event */
        switch(event.type)
        {
        case FUNCTIONFS_BIND:
        case FUNCTIONFS_UNBIND:
            break;

        case FUNCTIONFS_ENABLE:
            debugPrintf("ENABLE\n"); break;
        case FUNCTIONFS_DISABLE:
            debugPrintf("DISABLE\n"); break;

        case FUNCTIONFS_SETUP:
        {
            debugPrintf("Host: Received control packet\n");

            if((event.u.setup.bRequestType & USB_DIR_IN) == 0)
            {
                if(event.u.setup.wLength > USB_MAX_CTRL_SIZE)
                {
                    fprintf(stderr, "Packet too big\n");
                    return false;
                }

                uint8_t data[USB_MAX_CTRL_SIZE];
                if(!readPacketEP(0x80, data, event.u.setup.wLength))
                    perror("Warn: packet read");

                ep0_cb(event.u.setup, data, event.u.setup.wLength);
            }
            else
                ep0_cb(event.u.setup, nullptr, 0);

            return true;
        }

        case FUNCTIONFS_SUSPEND:
        case FUNCTIONFS_RESUME:
            debugPrintf("Suspend/Resume: TODO\n");
            break;

        default:
            fprintf(stderr, "Unknown EP0 event %d\n", event.type);
            // no return false here
            break;
        }
    }

    return true;
}

void USBFunctionFS::pauseProcessing(uint8_t ep)
try{
    endpoints.at(ep)->waiting_for_answer = true;
}catch(...) { __builtin_trap(); }

bool USBFunctionFS::processingPaused(uint8_t ep)
try{
    return endpoints.at(ep)->waiting_for_answer;
}catch(...) { __builtin_trap(); }

void USBFunctionFS::resumeProcessing(uint8_t ep)
try {
    endpoints.at(ep)->waiting_for_answer = false;
}catch(...) { __builtin_trap(); }

USBFunctionFS::EPData::~EPData()
{
    if(thread.joinable())
        thread.join();

    close(fd);
}

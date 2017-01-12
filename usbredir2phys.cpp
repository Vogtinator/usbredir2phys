#include <algorithm>
#include <cstdarg>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netdb.h>

#include <boost/program_options.hpp>

#include <usbredirparser.h>

extern "C" {
#include <usbg/usbg.h>
#include <linux/usb/functionfs.h>
}

#include "usbdevice.h"

/* Various constants */
const constexpr uint32_t EP_FORWARD = 0x71FEBEEF,
                         EP_PROCESS = 0xDEADBEEF;

/* Simple RAII deleter */
template<typename T>
using scope_ptr = std::unique_ptr<T, void(*)(T*)>;

/* Helper for RAII */
class TCPConnection {
public:
    TCPConnection() = default;
    TCPConnection(const TCPConnection &other) = delete;
    ~TCPConnection()
    {
        disconnect();
    }

    bool connect(const char *hostname, uint16_t port)
    {
        if(connected())
        {
            fprintf(stderr, "Already connected!\n");
            return false;
        }

        addrinfo hints{};
        addrinfo *res = nullptr;

        hints.ai_flags = AI_ADDRCONFIG | AI_NUMERICSERV;
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_protocol = IPPROTO_TCP;

        if(getaddrinfo(hostname, std::to_string(port).c_str(), &hints, &res) != 0)
            return false;

        scope_ptr<struct addrinfo> d(res, freeaddrinfo); (void) d;

        for(struct addrinfo *i = res; i != nullptr; i = i->ai_next)
        {
            if((fd = socket(i->ai_family, i->ai_socktype, i->ai_protocol)) == -1)
                continue;

            if(::connect(fd, i->ai_addr, i->ai_addrlen) == 0)
                break;

            close(fd);
            fd = -1;
        }

        return connected();
    }

    ssize_t write(void *data, size_t count)
    {
        if(!connected())
        {
            fprintf(stderr, "Not connected!\n");
            return -1;
        }

        auto r = ::write(fd, data, count);
        if(r == -1 && errno == EPIPE)
            disconnect();

        return r;
    }

    ssize_t read(void *data, size_t count)
    {
        if(!connected())
        {
            fprintf(stderr, "Not connected!\n");
            return -1;
        }

        auto r = ::read(fd, data, count);
        if(r == -1 && errno != EAGAIN && errno != EWOULDBLOCK)
            disconnect();

        return r;
    }

    bool connected()
    {
        return fd != -1;
    }

    void disconnect()
    {
        if(connected())
            close(fd);
    }

    int fd = -1;
};

template <typename T>
void appendToVector(std::vector<uint8_t> &v, const T &data)
{
    v.resize(v.size() + sizeof(T));
    memcpy(v.data() + v.size() - sizeof(T), &data, sizeof(T));
}

class USBFunctionFs {
public:
    USBFunctionFs(usbredirparser *urp)
        : urp(urp) {}

    USBFunctionFs(const USBFunctionFs &other) = delete;
    USBFunctionFs(USBFunctionFs&&) = default;
    USBFunctionFs& operator = (USBFunctionFs&&) = default;
    ~USBFunctionFs()
    {
        if(path.empty())
            return;

        if(dirfd >= 0)
            close(dirfd);

        for(auto fd : endpoints)
            close(fd.second);

        std::string command = std::string("umount " + path);
        system(command.c_str());

        rmdir(path.c_str());
    }

    bool create(std::string name)
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

    int openEP(uint8_t id)
    {
        char name[5];
        snprintf(name, sizeof(name), "ep%x", id);
        return openat(dirfd, name, O_RDWR | O_NONBLOCK);
    }

    bool writePacketEP(uint8_t ep, const uint8_t *data, size_t size)
    {
        auto &&ep_fd = endpoints.find(ep & 0x7f);
        if(ep_fd == endpoints.end())
            return false;

        return write(ep_fd->second, data, size) == ssize_t(size);
    }

    bool readPacketEP(uint8_t ep, uint8_t *data, size_t size)
    {
        auto &&ep_fd = endpoints.find(ep & 0x7f);
        if(ep_fd == endpoints.end())
            return false;

        return read(ep_fd->second, data, size) == ssize_t(size);
    }

    bool fill(const USBDevice &dev, const USBConfiguration &config)
    {
        int ep0 = openEP(0);

        if(ep0 == -1)
        {
            fprintf(stderr, "Could not open ep0!");
            return false;
        }

        endpoints[0] = ep0;

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

        e = write(ep0, request.data(), request.size());
        if(e != ssize_t(request.size()))
        {
            perror("FFS EP0 strss write");
            return false;
        }

        /* FFS does not use the EP address directly, only the endpoint number */

        for(auto&& intf : config.interfaces)
            for(auto&& epAddr : intf.endpoints)
            {
                if(endpoints.find(epAddr) != endpoints.end())
                {
                    perror("Duplicate EP address?");
                    return false;
                }

                auto epfd = openEP(epAddr & USB_ENDPOINT_NUMBER_MASK);
                if(epfd == -1)
                {
                    perror("FFS EP open");
                    return false;
                }

                endpoints[epAddr] = epfd;
            }

        return true;
    }

    /* For use with select. */
    void fillFDSet(fd_set *set_read, int *highest)
    {
        for(auto &&ep : endpoints)
        {
            // Only OUT endpoints need to be read
            if(ep.first & 0x80)
                continue;

            FD_SET(ep.second, set_read);
            if(ep.second > *highest)
                *highest = ep.second;
        }
    }

    bool handleEP0Data(int fd)
    {
        /* Read events until EOF or reponse needed */
        while(!waiting_for_data)
        {
            usb_functionfs_event event;
            auto r = read(fd, &event, sizeof(event));
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
                printf("ENABLE\n"); break;
            case FUNCTIONFS_DISABLE:
                printf("DISABLE\n"); break;

            case FUNCTIONFS_SETUP:
            {
                printf("Host: Received control packet\n");
                /* Send as control packet */
                usb_redir_control_packet_header header = {
                    .endpoint = uint8_t(event.u.setup.bRequestType & USB_DIR_IN),
                    .request = event.u.setup.bRequest,
                    .requesttype = event.u.setup.bRequestType,
                    .status = usb_redir_success,
                    .value = event.u.setup.wValue,
                    .index = event.u.setup.wIndex,
                    .length = event.u.setup.wLength
                };

                if((event.u.setup.bRequestType & 0x80) == 0)
                {
                    if(header.length > USB_MAX_CTRL_SIZE)
                    {
                        fprintf(stderr, "Packet too big\n");
                        return false;
                    }

                    uint8_t data[USB_MAX_CTRL_SIZE];
                    if(!readPacketEP(header.endpoint, data, header.length))
                        perror("Warn: packet read");

                    usbredirparser_send_control_packet(urp, EP_FORWARD, &header, data, header.length);
                }
                else
                    usbredirparser_send_control_packet(urp, EP_FORWARD, &header, nullptr, 0);

                waiting_for_data = true;

                return true;
            }

            case FUNCTIONFS_SUSPEND:
            case FUNCTIONFS_RESUME:
                printf("Suspend/Resume: TODO\n");
                break;

            default:
                fprintf(stderr, "Unknown EP0 event %d\n", event.type);
                // no return false here
                break;
            }
        }

        return true;
    }

    bool handleEPXData(uint8_t ep, int fd)
    {
        uint8_t buf[1024];
        auto r = read(fd, buf, sizeof(buf));
        if(r == 0 || (r < 0 && errno == EAGAIN))
            return true; // EOF
        else if(r < 0)
        {
            if(errno == EBADMSG)
            {
                fprintf(stderr, "Bad message\n");
                ioctl(fd, FUNCTIONFS_CLEAR_HALT);
                return true;
            }

            perror("EPX READ");
            return false;
        }

        usb_redir_bulk_packet_header header = {
            .endpoint = ep,
            .status = usb_redir_success,
            .length = uint16_t(r),
            .stream_id = 0,
            .length_high = uint16_t(r >> 16),
        };

        usbredirparser_send_bulk_packet(urp, EP_FORWARD, &header, buf, r);

        return true;
    }

    bool handleDataAvailable(fd_set *set)
    {
        bool ret = true;

        for(auto &&ep : endpoints)
        {
            if(!FD_ISSET(ep.second, set))
                continue;

            if(ep.first == 0)
                ret = ret && handleEP0Data(ep.second);
            else
                ret = ret && handleEPXData(ep.first, ep.second);
        }

        return ret;
    }

    /* After each event, a roundtrip over usbredir is required.
     * After the response arrived, call this to look at the next event. */
    void packetProcessed()
    {
        waiting_for_data = false;
    }

private:
    std::string path;
    int dirfd = -1;
    usbredirparser *urp;
    std::map<uint8_t, int> endpoints;
    bool waiting_for_data = false;
};

template<typename... Args>
void usbg_perror(usbg_error e, Args... args)
{
    fprintf(stderr, args...);
    fprintf(stderr, ": %s\n", usbg_strerror(e));
}

struct PrivUSBG {
    ~PrivUSBG() {
        usbg_error e;
        if(g != nullptr)
        {
            usbg_disable_gadget(g);
            if((e = usbg_error(usbg_rm_gadget(g, USBG_RM_RECURSE))) != USBG_SUCCESS)
                usbg_perror(e, "usbg_rm_gadget");
        }

        if(s != nullptr)
            usbg_cleanup(s);
    }

    usbg_state *s;
    usbg_gadget *g;
    usbg_function *f;
    usbg_config *c;
};

struct UR2PPriv {
    PrivUSBG usbg;
    TCPConnection con;
    scope_ptr<usbredirparser> parser{nullptr, usbredirparser_destroy};
    USBDevice device;

    /* To be requested */
    std::vector<uint32_t> missing_strings;

    enum {
        NO_IDEA,
        DEV_DESC_QUERIED,
        CONF_DESC_QUERIED,
        STR0_DESC_QUERIED,
        STR_DESC_QUERIED,
        FORWARDING
    } state;

    /* One per configuration.
     * Is the last member as it needs to be cleaned up first */
    std::vector<USBFunctionFs> ffs;
};

/* Set to false in the signal handler. */
static volatile bool keep_running = true;

void setup_signals()
{
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_flags |= SA_SIGINFO;
    sa.sa_sigaction = [](int, siginfo_t *, void *) { keep_running = false; };

    for(auto i : {SIGINT, SIGHUP, SIGTERM, SIGQUIT})
        sigaction(i, &sa, NULL);
}

bool gadget_init(UR2PPriv &priv)
{
    auto &dev = priv.device;

    usbg_gadget_attrs attrs = {
        .bcdUSB = dev.desc.bcdUSB,
        .bDeviceClass = dev.desc.bDeviceClass,
        .bDeviceSubClass = dev.desc.bDeviceSubClass,
        .bDeviceProtocol = dev.desc.bDeviceProtocol,
        .bMaxPacketSize0 = dev.desc.bMaxPacketSize0,
        .idVendor = dev.desc.idVendor,
        .idProduct = dev.desc.idProduct,
        .bcdDevice = dev.desc.bcdDevice,
    };

    auto serial = priv.device.strings.getUTF8(0x409, dev.desc.iSerialNumber),
            product = priv.device.strings.getUTF8(0x409, dev.desc.iProduct),
            manuf = priv.device.strings.getUTF8(0x409, dev.desc.iManufacturer);

    usbg_gadget_strs strs;

    strncpy(strs.str_ser, serial.c_str(), USBG_MAX_STR_LENGTH);
    strncpy(strs.str_prd, product.c_str(), USBG_MAX_STR_LENGTH);
    strncpy(strs.str_mnf, manuf.c_str(), USBG_MAX_STR_LENGTH);

    auto e = usbg_error(usbg_create_gadget(priv.usbg.s, "redir0", &attrs, &strs, &priv.usbg.g));
    if(e != USBG_SUCCESS)
    {
        usbg_perror(e, "usbg_create_gadget");
        return false;
    }

    /* Add configurations */
    uint8_t index = 0;
    for(uint8_t index = 0; index < dev.configs.size(); ++index)
    {
        auto &conf = dev.configs[index];
        auto sConfig = priv.device.strings.getUTF8(0x409, conf.desc.iConfiguration);

        usbg_config_strs c_strs;
        strncpy(c_strs.configuration, sConfig.c_str(), USBG_MAX_STR_LENGTH);

        char name[7];
        snprintf(name, sizeof(name), "conf%x", index);

        usbg_config *g_c;
        usbg_create_config(priv.usbg.g, 1, name, nullptr, &c_strs, &g_c);

        /* Each configuration has exactly one FFS function */
        usbg_function *g_f;
        snprintf(name, sizeof(name), "func%x", index);
        e = usbg_error(usbg_create_function(priv.usbg.g, F_FFS, name, nullptr, &g_f));
        if(e != USBG_SUCCESS)
        {
            usbg_perror(e, "usbg_create_function");
            return false;
        }

        usbg_add_config_function(g_c, name, g_f);

        /* Create the USBFunctionFS instance */
        priv.ffs.push_back({priv.parser.get()});
        USBFunctionFs &ffs = priv.ffs.back();
        if(!ffs.create(std::string{name}))
        {
            fprintf(stderr, "Could not create ffs!\n");
            return false;
        }

        if(!ffs.fill(dev, conf))
        {
            fprintf(stderr, "Could not fill ffs!\n");
            return false;
        }
    }

    e = usbg_error(usbg_enable_gadget(priv.usbg.g, nullptr));
    if(e != USBG_SUCCESS)
        fprintf(stderr, "usbg_enable_gadget: %s\n", usbg_strerror(e));

    priv.state = UR2PPriv::FORWARDING;
    return true;
}

/* Parser callbacks */
#define DECL_PRIV UR2PPriv &priv = *reinterpret_cast<UR2PPriv*>(ppriv)

void ur2p_log(void *, int, const char *msg)
{
    printf("%s\n", msg);
}

int ur2p_read(void *ppriv, uint8_t *data, int count)
{
    DECL_PRIV;

    ssize_t r = priv.con.read(data, size_t(count));

    if(r < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
        return 0;

    return int(r);
}

int ur2p_write(void *ppriv, uint8_t *data, int count)
{
    DECL_PRIV;

    ssize_t r = priv.con.write(data, size_t(count));

    if(r < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
        return 0;

    return int(r);
}

void ur2p_device_connect(void *ppriv, struct usb_redir_device_connect_header *)
{
    DECL_PRIV;

    if(priv.state != UR2PPriv::NO_IDEA)
    {
        fprintf(stderr, "Invalid state!\n");
        return;
    }

    usb_redir_control_packet_header header = {
        .endpoint = USB_DIR_IN,
        .request = USB_REQ_GET_DESCRIPTOR,
        .requesttype = USB_DIR_IN,
        .status = usb_redir_success,
        .value = (USB_DT_DEVICE << 8) | USB_RECIP_DEVICE,
        .index = 0,
        .length = sizeof(usb_device_descriptor)
    };

    usbredirparser_send_control_packet(priv.parser.get(), EP_PROCESS, &header, nullptr, 0);

    priv.state = UR2PPriv::DEV_DESC_QUERIED;
}

/* Unused. Can't be nullptr in the callback pointer struct as usbredirparser does not check... */
void ur2p_device_disconnect(void *) {}
void ur2p_interface_info(void *, struct usb_redir_interface_info_header *) {}
void ur2p_ep_info(void *, struct usb_redir_ep_info_header *) {}
void ur2p_configuration_status(void *ppriv, uint64_t id, struct usb_redir_configuration_status_header *config_status) {}
void ur2p_alt_setting_status(void *ppriv, uint64_t id, struct usb_redir_alt_setting_status_header *alt_setting_status) {}
void ur2p_iso_stream_status(void *ppriv, uint64_t id, struct usb_redir_iso_stream_status_header *iso_stream_status) {}
void ur2p_interrupt_receiving_status(void *ppriv, uint64_t id, struct usb_redir_interrupt_receiving_status_header *interrupt_receiving_status) {}
void ur2p_bulk_streams_status(void *ppriv, uint64_t id, struct usb_redir_bulk_streams_status_header *bulk_streams_status) {}

void ur2p_device_descriptor(UR2PPriv &priv, usb_device_descriptor *desc)
{
    priv.device.desc = *desc;

    if(priv.device.desc.bDescriptorType != USB_DT_DEVICE)
        fprintf(stderr, "Not a device descriptor?\n");
    else
        printf("Got device descriptor (%.4x:%.4x)\n", priv.device.desc.idVendor, priv.device.desc.idProduct);
}

void ur2p_config_descriptor(UR2PPriv &priv, uint8_t *data, int data_len)
{
    usb_config_descriptor desc;
    memcpy(&desc, data, sizeof(desc));
    data_len -= sizeof(usb_config_descriptor);
    data += sizeof(usb_config_descriptor);

    auto index = priv.device.configs.size();
    priv.device.configs.push_back({});

    USBConfiguration &current_conf = priv.device.configs[index];
    if(current_conf.desc.bDescriptorType != 0)
        fprintf(stderr, "Config already seen!\n");

    current_conf.desc = desc;
    current_conf.full_desc.insert(current_conf.full_desc.end(), data, data + data_len);

    if(desc.bDescriptorType != USB_DT_CONFIG)
        fprintf(stderr, "Not a config descriptor?\n");
    else
        printf("Configuration %lu\n", index);

    /* Step through data to collect additional descriptors */
    while(data_len > 0)
    {
        auto *d_type = reinterpret_cast<usb_string_descriptor*>(data);
        switch(d_type->bDescriptorType)
        {
        case USB_DT_INTERFACE:
        {
            if(unsigned(data_len) < sizeof(usb_interface_descriptor))
            {
                fprintf(stderr, "Invalid descriptor size\n");
                return;
            }

            usb_interface_descriptor idesc;
            memcpy(&idesc, data, sizeof(idesc));

            USBInterface intf;
            intf.desc = idesc;
            current_conf.interfaces.emplace_back(std::move(intf));

            printf("`Interface %d\n", idesc.bInterfaceNumber);
            break;
        }
        case USB_DT_ENDPOINT:
        {
            if(unsigned(data_len) < USB_DT_ENDPOINT_SIZE)
            {
                fprintf(stderr, "Invalid descriptor size\n");
                return;
            }

            if(current_conf.interfaces.size() == 0)
            {
                fprintf(stderr, "Endpoint without interface?\n");
                return;
            }

            usb_endpoint_descriptor edesc;
            memcpy(&edesc, data, size_t(data_len));

            /* Add endpoint */
            priv.device.endpoints[epAddrToIndex(edesc.bEndpointAddress)].desc = edesc;

            /* Add endpoint to interface */
            current_conf.interfaces.back().endpoints.push_back(edesc.bEndpointAddress);

            printf("\t`Endpoint 0x%.2x\n", edesc.bEndpointAddress);
            break;
        }
        case 0x21:
            printf("\t`HID descriptor\n");
            break;
        default:
            fprintf(stderr, "Unhandled case 0x%.2x\n", d_type->bDescriptorType);
            break;
        }

        if(data_len < d_type->bLength)
        {
            fprintf(stderr, "Invalid bLength!\n");
            return;
        }

        data_len -= d_type->bLength;
        data += d_type->bLength;
    }
}

void ur2p_string_descriptor(UR2PPriv &priv, usb_string_descriptor *desc, size_t size, uint64_t id)
{
    if(desc->bDescriptorType != USB_DT_STRING)
        fprintf(stderr, "Not a string descriptor!\n");

    size_t bytes = size - offsetof(usb_string_descriptor, wData);
    std::u16string string{reinterpret_cast<char16_t*>(desc->wData), bytes / 2};
    priv.device.strings.strings[uint32_t(id)] = string;
}

void ur2p_str0_descriptor(UR2PPriv &priv, usb_string_descriptor *desc, size_t size)
{
    if(desc->bDescriptorType != USB_DT_STRING)
        fprintf(stderr, "Not a string descriptor!\n");

    /* Save available lang ids */
    size -= offsetof(usb_string_descriptor, wData);
    for(unsigned int i = 0; i < size / 2; ++i)
        priv.device.strings.langs.push_back(desc->wData[i]);
}

void ur2p_control_packet(void *ppriv, uint64_t id, struct usb_redir_control_packet_header *control_packet, uint8_t *data, int data_len)
{
    DECL_PRIV;

    /* I don't understand the use of signed sizes... */
    assert(data_len >= 0);

    /* If the ID matches or we queried a string descriptor the packet is ours */
    if(id == EP_PROCESS || priv.state == UR2PPriv::STR_DESC_QUERIED)
    {
        /* Process input */
        if(priv.state == UR2PPriv::DEV_DESC_QUERIED)
        {
            if(size_t(data_len) != sizeof(usb_device_descriptor))
            {
                fprintf(stderr, "Invalid control packet len.\n");
                return;
            }

            ur2p_device_descriptor(priv, reinterpret_cast<usb_device_descriptor*>(data));
        }
        else if(priv.state == UR2PPriv::CONF_DESC_QUERIED)
        {
            if(size_t(data_len) < sizeof(usb_config_descriptor))
            {
                fprintf(stderr, "Invalid control packet len.\n");
                return;
            }

            ur2p_config_descriptor(priv, data, data_len);
        }
        else if(priv.state == UR2PPriv::STR0_DESC_QUERIED)
        {
            if(size_t(data_len) < sizeof(usb_string_descriptor))
            {
                fprintf(stderr, "Invalid control packet len.\n");
                return;
            }

            ur2p_str0_descriptor(priv, reinterpret_cast<usb_string_descriptor*>(data), size_t(data_len));
        }
        else if(priv.state == UR2PPriv::STR_DESC_QUERIED)
        {
            if(size_t(data_len) < sizeof(usb_string_descriptor))
            {
                fprintf(stderr, "Invalid control packet len.\n");
                return;
            }

            ur2p_string_descriptor(priv, reinterpret_cast<usb_string_descriptor*>(data), size_t(data_len), id);
        }

        /* Generate output */

        // Need to fetch config descriptors?
        if(priv.device.configs.size() != priv.device.desc.bNumConfigurations)
        {
            usb_redir_control_packet_header header = {
                .endpoint = USB_DIR_IN,
                .request = USB_REQ_GET_DESCRIPTOR,
                .requesttype = USB_DIR_IN,
                .status = usb_redir_success,
                .value = (USB_DT_CONFIG << 8) | USB_RECIP_DEVICE,
                .index = uint16_t(priv.device.configs.size()),
                .length = USB_MAX_CTRL_SIZE
            };

            usbredirparser_send_control_packet(priv.parser.get(), EP_PROCESS, &header, nullptr, 0);

            priv.state = UR2PPriv::CONF_DESC_QUERIED;
            return;
        }
        else if(priv.state == UR2PPriv::CONF_DESC_QUERIED)
        {
            /* Last config descriptor arrived, query STR0 descriptor for LANGID list */

            usb_redir_control_packet_header header = {
                .endpoint = USB_DIR_IN,
                .request = USB_REQ_GET_DESCRIPTOR,
                .requesttype = USB_DIR_IN,
                .status = usb_redir_success,
                .value = (USB_DT_STRING << 8) | 0,
                .index = 0,
                .length = USB_MAX_CTRL_SIZE
            };

            usbredirparser_send_control_packet(priv.parser.get(), EP_PROCESS, &header, nullptr, 0);

            priv.state = UR2PPriv::STR0_DESC_QUERIED;
            return;
        }

        if(priv.state == UR2PPriv::STR0_DESC_QUERIED)
        {
            /* Got STR0 descriptor, make a list of all referenced strings */

            std::vector<uint8_t> strings;
            /* Referenced by device descriptor */
            strings.insert(strings.end(), {priv.device.desc.iManufacturer, priv.device.desc.iProduct, priv.device.desc.iSerialNumber});
            /* Referenced by config descriptors */
            for(auto &c : priv.device.configs)
            {
                strings.push_back(c.desc.iConfiguration);
                /* References by interface descriptors */
                for(auto &i : c.interfaces)
                    strings.push_back(i.desc.iInterface);
            }

            for(auto i : strings)
            {
                if(i == 0)
                    continue;
                for(auto langid : priv.device.strings.langs)
                    priv.missing_strings.push_back(makeString(langid, i));
            }
        }

        // Need to fetch string descriptors?
        if(!priv.missing_strings.empty())
        {
            auto string = priv.missing_strings.back();
            priv.missing_strings.pop_back();

            usb_redir_control_packet_header header = {
                .endpoint = USB_DIR_IN,
                .request = USB_REQ_GET_DESCRIPTOR,
                .requesttype = USB_DIR_IN,
                .status = usb_redir_success,
                .value = uint16_t((USB_DT_STRING << 8) | stringIndex(string)),
                .index = stringLangID(string),
                .length = USB_MAX_CTRL_SIZE
            };

            usbredirparser_send_control_packet(priv.parser.get(), string, &header, nullptr, 0);

            priv.state = UR2PPriv::STR_DESC_QUERIED;
            return;
        }

        /* We got everything! Let's configure and boot up the gadget */
        if(!gadget_init(priv))
            keep_running = false;
    }
    else
        fprintf(stderr, "Got packet with unexpected id 0x%.8lx\n", id);
}

template <typename T>
    void ur2p_packet_handler(void *ppriv, uint64_t id, T *packet, uint8_t *data, int data_len)
{
    DECL_PRIV;

    printf("Device: Received %s (%d bytes)\n", typeid(T).name(), data_len);

    if(id == EP_FORWARD && priv.state == UR2PPriv::FORWARDING)
    {
        /* Forward packets */
        if(packet->endpoint & USB_DIR_IN)
        {
            if(!priv.ffs[0].writePacketEP(packet->endpoint, data, data_len))
                fprintf(stderr, "Packet send failed\n");
        }
        priv.ffs[0].packetProcessed();
    }
    else
        fprintf(stderr, "Got packet with unexpected id 0x%.8lx\n", id);

    if(data)
        usbredirparser_free_packet_data(priv.parser.get(), data);
}

template <>
    void ur2p_packet_handler<usb_redir_control_packet_header>(void *ppriv, uint64_t id, usb_redir_control_packet_header *packet, uint8_t *data, int data_len)
{
    DECL_PRIV;

    printf("Device: Received %s (%d bytes)\n", typeid(usb_redir_control_packet_header).name(), data_len);

    if(id == EP_FORWARD && priv.state == UR2PPriv::FORWARDING)
    {
        /* Forward packets */
        if(packet->endpoint & USB_DIR_IN)
        {
            if(!priv.ffs[0].writePacketEP(packet->endpoint, data, data_len))
                fprintf(stderr, "Packet send failed\n");
        }
        priv.ffs[0].packetProcessed();
    }
    else
        ur2p_control_packet(ppriv, id, packet, data, data_len);

    if(data)
        usbredirparser_free_packet_data(priv.parser.get(), data);
}

void ur2p_hello(void *, struct usb_redir_hello_header *header)
{
    printf("Connected to %.64s.\n", header->version);
}

int main(int argc, char **argv)
{
    UR2PPriv priv;

    priv.state = UR2PPriv::NO_IDEA;
    priv.usbg.s = nullptr;
    priv.usbg.g = nullptr;

    /* Parse options */
    char *endptr = nullptr;
    unsigned long port = 0;
    const char *hostname;

    if(argc < 3)
        goto usage;

    hostname = argv[1];
    port = strtoul(argv[2], &endptr, 10);

    if(port == 0 || port > 65535 || *endptr != 0)
    {
        usage:
        fprintf(stderr, "Usage: %s <hostname> <port>\n", argv[0]);
        return 1;
    }

    setup_signals();

    if(!priv.con.connect(hostname, uint16_t(port)))
    {
        fprintf(stderr, "Could not connect to %s:%lu\n", hostname, port);
        return 1;
    }

    int flags = fcntl(priv.con.fd, F_GETFL);
    if(flags == -1 || fcntl(priv.con.fd, F_SETFL, flags | O_NONBLOCK) == -1)
    {
        perror("Unable to set O_NONBLOCK");
        return 1;
    }

    auto ret = usbg_error(usbg_init("/sys/kernel/config", &priv.usbg.s));
    if(ret != USBG_SUCCESS)
    {
        fprintf(stderr, "Could not initialize usbg: %s\n", usbg_strerror(ret));
        fprintf(stderr, "Make sure configfs is mounted at /sys/kernel/config and the libcomposite kernel module is loaded.\n");
        return 1;
    }

    priv.parser = scope_ptr<usbredirparser>(usbredirparser_create(), usbredirparser_destroy);

    if(!priv.parser)
    {
        fprintf(stderr, "Could not create parser.\n");
        return 1;
    }

    usbredirparser *parser = priv.parser.get();

    parser->priv = &priv;
    parser->log_func = ur2p_log;
    parser->read_func = ur2p_read;
    parser->write_func = ur2p_write;
    parser->device_connect_func = ur2p_device_connect;
    parser->device_disconnect_func = ur2p_device_disconnect;
    parser->interface_info_func = ur2p_interface_info;
    parser->ep_info_func = ur2p_ep_info;
    parser->configuration_status_func = ur2p_configuration_status;
    parser->alt_setting_status_func = ur2p_alt_setting_status;
    parser->iso_stream_status_func = ur2p_iso_stream_status;
    parser->interrupt_receiving_status_func = ur2p_interrupt_receiving_status;
    parser->bulk_streams_status_func = ur2p_bulk_streams_status;
    parser->control_packet_func = ur2p_packet_handler<usb_redir_control_packet_header>;
    parser->bulk_packet_func = ur2p_packet_handler<usb_redir_bulk_packet_header>;
    parser->iso_packet_func = ur2p_packet_handler<usb_redir_iso_packet_header>;
    parser->hello_func = ur2p_hello;

    uint32_t caps[USB_REDIR_CAPS_SIZE] = {0};

    // fdo#99015
    //usbredirparser_caps_set_cap(caps, usb_redir_cap_64bits_ids);

    usbredirparser_init(parser, "UR2P 0.-1", caps, USB_REDIR_CAPS_SIZE, 0);

    puts("Initialized.");

    /* We need the connect packet first. */
    usbredirparser_send_reset(parser);
    usbredirparser_send_get_configuration(parser, 0);

    while(keep_running && priv.con.fd != -1)
    {
        fd_set rfds, wfds;
        FD_ZERO(&rfds);
        FD_ZERO(&wfds);

        int highest = priv.con.fd;

        FD_SET(priv.con.fd, &rfds);
        if(usbredirparser_has_data_to_write(parser))
            FD_SET(priv.con.fd, &wfds);

        for(auto && ffs : priv.ffs)
            ffs.fillFDSet(&rfds, &highest);

        if(select(highest + 1, &rfds, &wfds, nullptr, nullptr) == -1)
        {
            if(errno == EINTR)
                continue;

            perror("select");
            break;
        }

        for(auto && ffs : priv.ffs)
        {
            if(!ffs.handleDataAvailable(&rfds))
                keep_running = false;
        }

        if(FD_ISSET(priv.con.fd, &rfds) && usbredirparser_do_read(parser) != 0)
        {
            fprintf(stderr, "Read error.\n");
            break;
        }

        if(FD_ISSET(priv.con.fd, &wfds) && usbredirparser_do_write(parser) != 0)
        {
            fprintf(stderr, "Write error.\n");
            break;
        }
    }

    printf("Shutting down....\n");
}

#include <cstdarg>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include <fcntl.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#include <boost/program_options.hpp>

#include <usbredirparser.h>

extern "C" {
#include <usbg/usbg.h>
}

/* Simple RAII deleter */
template<typename T>
using scope_ptr = std::unique_ptr<T, void(*)(T*)>;

/* Helper for RAII */
class TCPConnection {
public:
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

        struct addrinfo hints{};
        struct addrinfo *res = nullptr;

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

class USBFunctionFs {
public:
    ~USBFunctionFs()
    {
        if(path.empty())
            return;
    }

    bool create(std::string name)
    {
        // Check for invalid name
        if(name.find('\'') != std::string::npos)
            return false;

        char tmpname[] = "ffsXXXXXX";
        if(mkdtemp(tmpname) == nullptr)
            return false;

        path = tmpname;

        std::string command = std::string("mount -t functionfs '" + name + "' " + path);
        if(system(command.c_str()) == 0)
                return true;

        rmdir(path.c_str());
        path = "";
        return false;
    }

private:
    std::string path;
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
        if(g != nullptr && (e = usbg_error(usbg_rm_gadget(g, USBG_RM_RECURSE))) != USBG_SUCCESS)
            usbg_perror(e, "usbg_rm_gadget");

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
    usb_redir_interface_info_header ifs;
    usb_redir_ep_info_header eps;
    std::vector<USBFunctionFs> functions;
    enum {
        NO_IDEA,
        INTERFACES_READY,
        ENDPOINTS_READY,
        GADGET_READY,
    } state;
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

void ur2p_device_connect(void *ppriv, struct usb_redir_device_connect_header *header)
{
    DECL_PRIV;

    if(priv.state != UR2PPriv::ENDPOINTS_READY)
    {
        fprintf(stderr, "Invalid state!\n");
        return;
    }

    usbg_gadget_attrs attrs = {
        .bcdUSB = 0x0200,
        .bDeviceClass = header->device_class,
        .bDeviceSubClass = header->device_subclass,
        .bDeviceProtocol = header->device_protocol,
        .bMaxPacketSize0 = static_cast<uint8_t>(priv.eps.max_packet_size[0]),
        .idVendor = header->vendor_id,
        .idProduct = header->product_id,
        .bcdDevice = header->device_version_bcd,
    };

    usbg_gadget_strs strs = {
        "42",
        "SUSE Linux GmbH",
        "Virtual crashfest"
    };

    auto e = usbg_error(usbg_create_gadget(priv.usbg.s, "redir0", &attrs, &strs, &priv.usbg.g));
    if(e != USBG_SUCCESS)
        usbg_perror(e, "usbg_create_gadget");
    else
    {
        printf("Got device %.4x:%.4x\n", header->vendor_id, header->product_id);
        priv.state = UR2PPriv::GADGET_READY;

        e = usbg_error(usbg_create_function(priv.usbg.g, F_FFS, "func0", NULL, &priv.usbg.f));
        if(e != USBG_SUCCESS)
            usbg_perror(e, "usbg_create_gadget");

        usbg_config_strs c_strs = {
                "FUZZ"
        };

        usbg_create_config(priv.usbg.g, 1, "conf0", NULL, &c_strs, &priv.usbg.c);

        usbg_add_config_function(priv.usbg.c, "confun0", priv.usbg.f);

        e = usbg_error(usbg_enable_gadget(priv.usbg.g, nullptr));
        if(e != USBG_SUCCESS)
            fprintf(stderr, "usbg_enable_gadget: %s\n", usbg_strerror(e));
    }
}

void ur2p_device_disconnect(void *)
{
    printf("device disconnected");
}

void ur2p_interface_info(void *ppriv, struct usb_redir_interface_info_header *header)
{
    DECL_PRIV;

    if(priv.state != UR2PPriv::NO_IDEA)
    {
        fprintf(stderr, "Invalid state!\n");
        return;
    }

    for (unsigned int i = 0; i < header->interface_count; i++) {
        printf("interface %d class %2d subclass %2d protocol %2d\n",
               header->interface[i], header->interface_class[i],
               header->interface_subclass[i], header->interface_protocol[i]);
    }

    priv.state = UR2PPriv::INTERFACES_READY;
}

void ur2p_ep_info(void *ppriv, struct usb_redir_ep_info_header *ep_info)
{
    DECL_PRIV;

    if(priv.state != UR2PPriv::INTERFACES_READY)
    {
        fprintf(stderr, "Invalid state!\n");
        return;
    }

    for (int i = 0; i < 32; i++) {
       if (ep_info->type[i] != usb_redir_type_invalid) {
           printf("endpoint: %02X, type: %d, interval: %d, interface: %d\n",
                  i, (int)ep_info->type[i], (int)ep_info->interval[i],
                  (int)ep_info->interface[i]);
       }
    }

    priv.state = UR2PPriv::ENDPOINTS_READY;
}

void ur2p_configuration_status(void *ppriv, uint64_t id, struct usb_redir_configuration_status_header *config_status)
{
    DECL_PRIV;
}

void ur2p_alt_setting_status(void *ppriv, uint64_t id, struct usb_redir_alt_setting_status_header *alt_setting_status)
{
    DECL_PRIV;
}

void ur2p_iso_stream_status(void *ppriv, uint64_t id, struct usb_redir_iso_stream_status_header *iso_stream_status)
{
    DECL_PRIV;
}

void ur2p_interrupt_receiving_status(void *ppriv, uint64_t id, struct usb_redir_interrupt_receiving_status_header *interrupt_receiving_status)
{
    DECL_PRIV;
}

void ur2p_bulk_streams_status(void *ppriv, uint64_t id, struct usb_redir_bulk_streams_status_header *bulk_streams_status)
{
    DECL_PRIV;
}

void ur2p_control_packet(void *ppriv, uint64_t id, struct usb_redir_control_packet_header *control_packet, uint8_t *data, int data_len)
{
    DECL_PRIV;
}

void ur2p_bulk_packet(void *ppriv, uint64_t id, struct usb_redir_bulk_packet_header *bulk_packet, uint8_t *data, int data_len)
{
    DECL_PRIV;
}

void ur2p_iso_packet(void *ppriv, uint64_t id, struct usb_redir_iso_packet_header *iso_packet, uint8_t *data, int data_len)
{
    DECL_PRIV;
}

void ur2p_interrupt_packet(void *ppriv, uint64_t id, struct usb_redir_interrupt_packet_header *interrupt_packet, uint8_t *data, int data_len)
{
    DECL_PRIV;
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

    scope_ptr<usbredirparser> parser(usbredirparser_create(), usbredirparser_destroy);

    if(!parser)
    {
        fprintf(stderr, "Could not create parser.\n");
        return 1;
    }

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
    parser->control_packet_func = ur2p_control_packet;
    parser->bulk_packet_func = ur2p_bulk_packet;
    parser->iso_packet_func = ur2p_iso_packet;
    parser->hello_func = ur2p_hello;

    uint32_t caps[USB_REDIR_CAPS_SIZE] = {0};

    usbredirparser_caps_set_cap(caps, usb_redir_cap_connect_device_version);
    usbredirparser_caps_set_cap(caps, usb_redir_cap_ep_info_max_packet_size);
    usbredirparser_caps_set_cap(caps, usb_redir_cap_64bits_ids);

    usbredirparser_init(parser.get(), "UR2P 0.-1", caps, USB_REDIR_CAPS_SIZE, 0);

    puts("Initialized.");

    /* We need the connect packet first. */
    usbredirparser_send_reset(parser.get());
    usbredirparser_send_get_configuration(parser.get(), 0);

    while(keep_running && priv.con.fd != -1)
    {
        fd_set rfds, wfds;
        FD_ZERO(&rfds);
        FD_ZERO(&wfds);

        FD_SET(priv.con.fd, &rfds);
        if(usbredirparser_has_data_to_write(parser.get()))
            FD_SET(priv.con.fd, &wfds);

        if(select(priv.con.fd + 1, &rfds, &wfds, NULL, NULL) == -1)
        {
            if(errno == EINTR)
                continue;

            perror("select");
            break;
        }

        if(FD_ISSET(priv.con.fd, &rfds) && usbredirparser_do_read(parser.get()) != 0)
        {
            fprintf(stderr, "Read error.\n");
            break;
        }

        if(FD_ISSET(priv.con.fd, &wfds) && usbredirparser_do_write(parser.get()) != 0)
        {
            fprintf(stderr, "Write error.\n");
            break;
        }
    }

    printf("Shutting down....\n");
}

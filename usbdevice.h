#ifndef USBDEVICE_H
#define USBDEVICE_H

#include <codecvt>
#include <locale>
#include <map>
#include <string>
#include <vector>

#include <linux/usb/ch9.h>

/* Although the max len supported is 65536,
 * libusb rejects anything over 4096 as "Windows does not support it".
 * *facedesk*
 */
#define USB_MAX_CTRL_SIZE 4096

constexpr size_t epAddrToIndex(uint8_t a)
{
    return (a & 0x80 >> 3) | (a & 0xF);
}

constexpr uint8_t stringIndex(uint32_t str)
{
    return str & 0xFF;
}

constexpr uint16_t stringLangID(uint32_t str)
{
    return str >> 16;
}

constexpr uint32_t makeString(uint16_t langid, uint8_t index)
{
    return langid << 16 | index;
}

struct USBEndpoint {
    usb_endpoint_descriptor desc;
};

struct USBInterface {
    usb_interface_descriptor desc;
    /* Addresses of endpoints.
     * Use epAddrToIndex to get the index into USBDevice::endpoints. */
    std::vector<uint8_t> endpoints;
};

struct USBConfiguration {
    usb_config_descriptor desc;
    std::vector<USBInterface> interfaces;
    /* The whole blob receviced, containing IFs, EPs
     * and unrecognized descriptors */
    std::vector<uint8_t> full_desc;
};

struct USBStrings {
    std::vector<uint16_t> langs;
    // Use makeString as index
    std::map<uint32_t, std::u16string> strings;

    std::string getUTF8(uint16_t lang, uint8_t index) const
    {
        auto key = makeString(lang, index);
        if(index == 0 || strings.count(key) == 0)
            return {};

        std::wstring_convert<std::codecvt_utf8_utf16<char16_t>, char16_t> conv;
        return conv.to_bytes(strings.at(key));
    }
};

struct USBDevice {
    usb_device_descriptor desc;
    uint8_t active_config;
    std::vector<USBConfiguration> configs;
    USBEndpoint endpoints[32];
    USBStrings strings;
};

#endif // USBDEVICE_H

#ifndef USBDEVICE_H
#define USBDEVICE_H

#include <map>
#include <string>
#include <vector>

#include "usb.h"

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
};

struct USBStrings {
    std::vector<uint16_t> langs;
    // Use makeString as index
    std::map<uint32_t, std::u16string> strings;
};

struct USBDevice {
    usb_device_descriptor desc;
    uint8_t active_config;
    std::vector<USBConfiguration> configs;
    USBEndpoint endpoints[32];
    USBStrings strings;
};

#endif // USBDEVICE_H

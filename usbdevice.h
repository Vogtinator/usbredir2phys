#ifndef USBDEVICE_H
#define USBDEVICE_H

#include <map>
#include <string>
#include <vector>

#include "usb.h"

constexpr size_t epAddrToIndex(uint8_t a)
{
    return (a >> 3) | (a & 0xF);
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

struct USBDevice {
    usb_device_descriptor desc;
    uint8_t active_config;
    std::map<uint8_t, USBConfiguration> configs;
    USBEndpoint endpoints[32];
    std::vector<std::u16string> strings;
};

#endif // USBDEVICE_H

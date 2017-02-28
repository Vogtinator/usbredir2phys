usbredir2phys
-------------

This tool can be used to turn virtual USB connections (usbredir) into physical ones by utilizing the linux USB gadget stack.

Usage
-----

Just run

```
usbredir2phys <ip> <port>
```

to connect to a usbredir server at ```<ip>:<port>```.
usbredir2phys will start to query all descriptors, setup a composite device using libusbgx, add a new USB FFS function for each configuration and start to listen for events on each function.

Known limitations
-----------------

Multiple configurations are not fully implemented yet.
They will be configured and set up internally, but switching from the host will not have any effect on the device (no setConfiguration packet sent)
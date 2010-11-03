pcaplua
==========

What's it?
----------

It's a Lua binding for the ``libpcap`` library, used by ``tcpdump``, WireShark and many others.

Module Functions
----------------

**pcaplua.new_live_capture([dev [, promisc]])**

Creates a new capture object.  The first parameter is the name of the network device to be used for packet capture.  If omitted, the first one available to the user is selected, as returned by ``pcap_lookupdev()``.  If the second parameter is committed, **nil** or **false**, the device is **not** put on promisc mode. (Note that it could already be on that mode).

If successful, returns the capture object created, and a string with the device name used.  On failure, raises an error with a (hopefully) relevant message.


**decode_ethernet (packet [, table])**

**decode_ip (packet [, table])**

**decode_tcp (packet [, table])**

**decode_udp (packet [, table])**

All these functions receive a packet data in the form of a string holding the binary data of the packet and return a table filled with all the information in the packet's header.  The second parameter is the table to be filled with the header field's data.  If omitted, a new table is allocated.  If present, it won't be erased before setting new fields, so any data that isn't overwritten, would be preserved.

Besides the header fields, it also sets a `content` field with the payload data.  That makes it possible to write::

  pcaplua.decode_ip(pcaplua.decode_ethernet(d).content).src

if, for example, all you need is the source IP number

Capture Object Methods
----------------------

**cap:set_filter (filtercode)**

Compiles and sets the filter code.  Returns nothing.  Can raise errors on missing parameter, filter compiling, and installing the filter on the capture object.

**cap:next ()**

Captures one packet from the capture object.  Can block indefinitely until an object complying with the filter code (if any) is captured.

Returns the packet data as string (ready for ``decode_ethernet()``), the packet's capture time as a float (with microsecond resolution), and the wire length of the packet.

**cap:getcallback ()**

**cap:setcallback (handler)**

**cap:loop ([n])**

This is the main use of the library: ``handler`` is a function (or a callable object), like ``function handler (pkt, time, len)`` by ``loop()`` for each packet that complies with the filter installed (if any).  The optional ``n`` is a limit on how many packets to capture.  If 0 or missing there's no limit, it would keep capturing and calling ``handler`` until signalled.

If the handler returns any value or raises an error, the loop is interrupted.

``cap:loop()`` returns first the number of captured packets or **nil** if there was an error, followed by the value(s) returned by ``handler``.

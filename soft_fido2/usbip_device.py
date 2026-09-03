'''
Copyright (c) 2014 Yaron Shani <yaron.shani@gmail.com>.
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:

   1. Redistributions of source code must retain the above copyright
      notice, this list of conditions and the following disclaimer.

   2. Redistributions in binary form must reproduce the above
      copyright notice, this list of conditions and the following
      disclaimer in the documentation and/or other materials provided
      with the distribution.

This software is provided ``as is'' and any express or implied
warranties, including, but not limited to, the implied warranties of
merchantability and fitness for a particular purpose are
disclaimed. In no event shall author or contributors be liable for any
direct, indirect, incidental, special, exemplary, or consequential
damages (including, but not limited to, procurement of substitute
goods or services; loss of use, data, or profits; or business
interruption) however caused and on any theory of liability, whether
in contract, strict liability, or tort (including negligence or
otherwise) arising in any way out of the use of this software, even if
advised of the possibility of such damage.

Update 2022 by Lachlan Gleeson for python 3
'''

import socketserver, datetime, struct, traceback, re, signal, threading, random, time, logging
from typing import Optional

from .ctaphid_protocol import BaseStructure as _BaseStructure, bcolors, colour_print, CTAPHIDInitPkt, CTAPHIDSeqPkt
from .passkey_device import CBORCommand
from enum import Enum

def print_bytes(*args):
    result = ""
    count = 0
    for ba in args:
        for x in ba:
            result += "%02X " % x
            count += 1
            if count == 8 :
                result += " "
            elif count == 16:
                print("\t" + result)
                result = ""
                count = 0
    print('\t' + result + '\n')

def dump_bytes(*args, colour=bcolors.OKPURPLE, component='USB/IP CONTROLLER', msg=''):
    #Print bytes in nice format
    c = colour if colour != None else bcolors.OKPURPLE
    colour_print(colour=colour, component=component, msg=msg)
    print_bytes(*args)


class BaseStructure(_BaseStructure):
    """USB/IP protocol structure base.

    Overrides byte-order to big-endian (``>``) and adds ``__getattr__``
    so that accessing an undefined field returns ``None`` rather than
    raising ``AttributeError``.  Also provides ``formatDevicesList`` /
    ``packDevicesList`` for multi-device list encoding.
    """
    base_pack_format = '>'

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        # `__getattr__` below makes `hasattr` always return True, so the base
        # __init__ never applies field defaults. Apply them here explicitly.
        for field in self._fields_:
            if len(field) > 2 and getattr(self, field[0], None) is None:
                setattr(self, field[0], field[2])

    def __getattr__(self, name):
        """Return None for undefined attributes instead of raising AttributeError."""
        return None

    def format(self):
        pack_format = self.base_pack_format
        for field in self._fields_:
            if isinstance(field[1], BaseStructure):
                pack_format += str(field[1].size()) + 's'
            elif 'si' == field[1]:
                pack_format += 'c'
            elif '<' in field[1] or '>' in field[1]:
                pack_format += field[1][1:]
            else:
                pack_format += field[1]
        return pack_format.encode('utf-8')

    def formatDevicesList(self, devicesCount):

        pack_format = '>'
        i = 0
        for field in self._fields_:
            if (i == devicesCount + 2):
                break
            if isinstance(field[1], BaseStructure):
                pack_format += str(field[1].size()) + 's'
            elif 'si' == field[1]:
                pack_format += 'c'
            elif '<' in field[1]:
                pack_format += field[1][1:]
            else:
                pack_format += field[1]
            i += 1
        #print(pack_format)
        return pack_format.encode('utf-8')

    def pack(self):
        values = []
        for field in self._fields_:
            #print("Field: {}".format(field))
            if isinstance(field[1], BaseStructure):
                attr_val = getattr(self, field[0], None)
                if attr_val is not None and hasattr(attr_val, 'pack'):
                    values.append(attr_val.pack())
                else:
                    # If attribute doesn't exist or isn't a BaseStructure, use default
                    values.append(field[1].pack() if hasattr(field[1], 'pack') else b'')
            elif re.match(r'\d*x', field[1]):
                #Skipp padding
                continue
            else:
                if 'si' == field[1]:
                    values.append(chr(getattr(self, field[0], 0)))
                else:
                    values.append(getattr(self, field[0], 0))
        #Python 2 -> 3, str != bytestring so conditionally remap any strings we find.
        values = [bytes(v, 'utf-8') if isinstance(v, str) else v for v in values]
        #print(values)
        packed = struct.pack(self.format(), *values)
        #print("packed [{}]".format(packed))
        return packed 

    def packDevicesList(self, devicesCount):
        values = []
        i = 0
        for field in self._fields_:
            if (i == devicesCount + 2):
                break
            if isinstance(field[1], BaseStructure):
                attr_val = getattr(self, field[0], None)
                if attr_val is not None and hasattr(attr_val, 'pack'):
                    values.append(attr_val.pack())
                else:
                    # If attribute doesn't exist or isn't a BaseStructure, use default
                    values.append(field[1].pack() if hasattr(field[1], 'pack') else b'')
            else:
                if 'si' == field[1]:
                    values.append(chr(getattr(self, field[0], 0)))
                else:
                    values.append(getattr(self, field[0], 0))
            i += 1
        return struct.pack(self.formatDevicesList(devicesCount), *values)

    def unpack(self, buf):
        values = struct.unpack(self.format(), buf)
        i=0
        keys_vals = {}
        for val in values:
            if '<' in self._fields_[i][1][0]:
                val = struct.unpack('<' +self._fields_[i][1][1], struct.pack('>' + self._fields_[i][1][1], val))[0]
            keys_vals[self._fields_[i][0]]=val
            i+=1
        #print(keys_vals)
        self.init_from_dict(**keys_vals)


class USBIPHeader(BaseStructure):
    _fields_ = [
        ('version', 'H', 273),
        ('command', 'H'),
        ('status', 'I')
    ]


class USBInterface(BaseStructure):
    _fields_ = [
        ('bInterfaceClass', 'B'),
        ('bInterfaceSubClass', 'B'),
        ('bInterfaceProtocol', 'B'),
        ('align', 'B', 0)
    ]

class USBIPDevice(BaseStructure):
    _fields_ = [
        ('usbPath', '256s'),
        ('busID', '32s'),
        ('busnum', 'I'),
        ('devnum', 'I'),
        ('speed', 'I'),
        ('idVendor', 'H'),
        ('idProduct', 'H'),
        ('bcdDevice', 'H'),
        ('bDeviceClass', 'B'),
        ('bDeviceSubClass', 'B'),
        ('bDeviceProtocol', 'B'),
        ('bConfigurationValue', 'B'),
        ('bNumConfigurations', 'B'),
        ('bNumInterfaces', 'B'),
        ('interfaces', USBInterface())
    ]

class OPREPDevList(BaseStructure):

    def __init__(self, dictArg, count):
        self._fields_ = [
            ('base', USBIPHeader(), USBIPHeader(command=5,status=0)), # Declare this here to make sure it's in the right order
            ('nExportedDevice', 'I', count) # Same for this guy
        ]

        for key, value in dictArg.items():
            field = (str(key), value[0], value[1])
            self._fields_.append(field)

        super().__init__()

class OPREPImport(BaseStructure):
    _fields_ = [
        ('base', USBIPHeader()),
        ('usbPath', '256s'),
        ('busID', '32s'),
        ('busnum', 'I'),
        ('devnum', 'I'),
        ('speed', 'I'),
        ('idVendor', 'H'),
        ('idProduct', 'H'),
        ('bcdDevice', 'H'),
        ('bDeviceClass', 'B'),
        ('bDeviceSubClass', 'B'),
        ('bDeviceProtocol', 'B'),
        ('bConfigurationValue', 'B'),
        ('bNumConfigurations', 'B'),
        ('bNumInterfaces', 'B')
    ]

# https://www.kernel.org/doc/html/v5.14/usb/usbip_protocol.html

class USBIPRETSubmit(BaseStructure):

    '''
    def __init__(self, **kwargs):
        if 'data_frame' in kwargs:
            self._fields_ += [('data_frame', "%ds" % len(kwargs['data_frame']))]
            print(self._fields_)
        super(USBIPRETSubmit, self).__init__(**kwargs)
    '''

    _fields_ = [
        ('command', 'I'),
        ('seqnum', 'I'),
        ('devid', 'I'),
        ('direction', 'I'),
        ('ep', 'I'),
        ('status', 'I'),
        ('actual_length', 'I'),
        ('start_frame', 'I'),
        ('number_of_packets', 'I'),
        ('error_count', 'I'),
        ('padding', 'Q')
    ]

    data_frame: bytes | str = b''

    def pack(self):
        packed_data = BaseStructure.pack(self)
        #print("packed_data: [{}]".format(packed_data))
        #print("self.data: [{}]".format(self.data))
        if isinstance(self.data_frame, str):
            self.data_frame = self.data_frame.encode()
        packed_data += self.data_frame
        return packed_data

class USBIPCMDUnlink(BaseStructure):
    _fields_ = [
        ('seqnum', 'I'),
        ('devid', 'I'),
        ('direction', 'I'),
        ('ep', 'I'),
        ('seqnum2', 'I'),
    ]

'''
class USBIBCMDBasic(BaseStructure):
    _fields_ = [
        ('command', 'I'), #0x1
        ('seqnum', 'I'),
        ('devid', 'I'),
        ('direction', 'I'),
        ('ep', 'I')
    ]
'''

class USBIPCMDSubmit(BaseStructure):
    _fields_ = [
        ('command', 'I'),
        ('seqnum', 'I'),
        ('devid', 'I'),
        ('direction', 'I'),
        ('ep', 'I'),
        ('transfer_flags', 'I'),
        ('transfer_buffer_length', 'I'),
        ('start_frame', 'I'),
        ('number_of_packets', 'I'),
        ('interval', 'I'),
        ('setup', 'Q')
    ]

class USBIPUnlinkReq(BaseStructure):
    _fields_ = [
        ('seqnum', 'I'),
        ('devid', 'I'),
        ('direction', 'I'),
        ('ep', 'I'),
        ('unlink_seqnum', 'I'),
        ('padding', '24x')
    ]

class USBIPUnlinkRet(BaseStructure):
    _fields_ = [
        ('command', 'I', 0x4),
        ('seqnum', 'I'),
        ('devid', 'I', 0x2),
        ('direction', 'I'),
        ('ep', 'I'),
        ('status', 'I'),
        ('padding', '24x')
    ]


class USBDescriptor(BaseStructure):
    """USB descriptor structures are little-endian per the USB spec.

    ``BaseStructure`` is big-endian (correct for the USB/IP wire protocol),
    but descriptor blobs sent to the host must be little-endian. All USB
    descriptor classes below inherit from this.
    """
    base_pack_format = '<'


class StandardDeviceRequest(USBDescriptor):
    """USB control transfer SETUP packet (8 bytes, all little-endian)."""
    _fields_ = [
        ('bmRequestType', 'B'),
        ('bRequest', 'B'),
        ('wValue', 'H'),
        ('wIndex', 'H'),
        ('wLength', 'H')
    ]

class DeviceDescriptor(USBDescriptor):
    _fields_ = [
        ('bLength', 'B', 18),
        ('bDescriptorType', 'B', 1),
        ('bcdUSB', 'H', 0x0200),  # USB 2.0
        ('bDeviceClass', 'B'),
        ('bDeviceSubClass', 'B'),
        ('bDeviceProtocol', 'B'),
        ('bMaxPacketSize0', 'B'),
        ('idVendor', 'H'),
        ('idProduct', 'H'),
        ('bcdDevice', 'H'),
        ('iManufacturer', 'B'),
        ('iProduct', 'B'),
        ('iSerialNumber', 'B'),
        ('bNumConfigurations', 'B')
    ]


class DeviceQualifierDescriptor(USBDescriptor):
    """USB 2.0 device qualifier descriptor (type 0x06, exactly 10 bytes)."""
    _fields_ = [
        ('bLength', 'B', 10),
        ('bDescriptorType', 'B', 0x06),
        ('bcdUSB', 'H', 0x0200),
        ('bDeviceClass', 'B'),
        ('bDeviceSubClass', 'B'),
        ('bDeviceProtocol', 'B'),
        ('bMaxPacketSize0', 'B', 8),
        ('bNumConfigurations', 'B', 1),
        ('bReserved', 'B', 0),
    ]

class DeviceConfigurations(USBDescriptor):
    _fields_ = [
        ('bLength', 'B', 9),
        ('bDescriptorType', 'B', 2),
        ('wTotalLength', 'H', 41),  # config+interface+HID+2 endpoints = 41
        ('bNumInterfaces', 'B', 1),
        ('bConfigurationValue', 'B', 1),
        ('iConfiguration', 'B', 0),
        ('bmAttributes', 'B', 0x80),
        ('bMaxPower', 'B', 0x32)
    ]


class InterfaceDescriptor(USBDescriptor):
    _fields_ = [
        ('bLength', 'B', 9),
        ('bDescriptorType', 'B', 4),
        ('bInterfaceNumber', 'B', 0),
        ('bAlternateSetting', 'B', 0),
        ('bNumEndpoints', 'B', 1),
        ('bInterfaceClass', 'B', 3),
        ('bInterfaceSubClass', 'B', 1),
        ('bInterfaceProtocol', 'B', 2),
        ('iInterface', 'B', 0)
    ]


class EndPoint(USBDescriptor):
    _fields_ = [
        ('bLength', 'B', 7),
        ('bDescriptorType', 'B', 0x5),
        ('bEndpointAddress', 'B', 0x81),
        ('bmAttributes', 'B', 0x3),
        ('wMaxPacketSize', 'H', 0x0040),
        ('bInterval', 'B', 0x0A)
    ]



class USBRequest():
    """USB request object with dynamic attributes."""
    def __init__(self, **kwargs):
        # Define expected attributes with defaults
        self.seqnum = None
        self.devid = None
        self.direction = None
        self.ep = None
        self.flags = None
        self.number_of_packets = None
        self.interval = None
        self.setup = None
        self.start_frame = None
        self.data_frame = b''
        self.cmd_frame = b''
        self.unlink_seqnum = None
        
        # Set attributes from kwargs
        for key, value in kwargs.items():
            setattr(self, key, value)


class USBDevice():
    '''Base USB/IP device class
    
    Subclasses must define these class attributes:
    - speed: USB speed (2 for high-speed)
    - vendorID: USB vendor ID
    - productID: USB product ID
    - bcdDevice: Device release number
    - bDeviceClass: USB device class
    - bDeviceSubClass: USB device subclass
    - bDeviceProtocol: USB device protocol
    - bNumConfigurations: Number of configurations
    - bConfigurationValue: Configuration value
    - bNumInterfaces: Number of interfaces
    - configurations: List of DeviceConfigurations
    '''
    
    # Default values (should be overridden by subclasses)
    speed = 2
    vendorID = 0xc410
    productID = 0x0
    bcdDevice = 0x0
    bDeviceClass = 0x0
    bDeviceSubClass = 0x0
    bDeviceProtocol = 0x0
    bNumConfigurations = 1
    bConfigurationValue = 1
    bNumInterfaces = 1
    configurations = []
    # USB string descriptors (index 1=manufacturer, 2=product, 3=serial).
    # Empty strings leave the corresponding index unanswered (STALL-ish).
    manufacturer_string = ""
    product_string = ""
    serial_string = ""

    @staticmethod
    def _usb_string_descriptor(text):
        """Pack a UTF-16LE USB string descriptor (type 0x03)."""
        utf16 = text.encode('utf-16-le')
        return bytes([len(utf16) + 2, 0x03]) + utf16

    def _usb_string_descriptor_by_index(self, index):
        """Return the packed string descriptor for a string index, or b''."""
        if index == 0:
            data = (0x0409).to_bytes(2, 'little')  # English (US) LANGID
            return bytes([len(data) + 2, 0x03]) + data
        strings = {
            1: self.manufacturer_string,
            2: self.product_string,
            3: self.serial_string,
        }
        if index in strings and strings[index]:
            return self._usb_string_descriptor(strings[index])
        return b''

    def __init__(self):
        self.generate_raw_configuration()
        self.start_time = datetime.datetime.now()
        self.connection = None  # Will be set by USBIPConnection
    
    def handle_unknown_control(self, control_req, usb_req) -> bool:
        """Handle unknown control requests. Override in subclass.
        
        Returns:
            bool: True if handled, False otherwise
        """
        return False
    
    def handle_data(self, usb_req):
        """Handle data requests. Override in subclass."""
        pass

    def generate_raw_configuration(self):
        _str = self.configurations[0].pack()
        _str += self.configurations[0].interfaces[0].pack()
        _str += self.configurations[0].interfaces[0].descriptions[0].pack()
        #_str += self.configurations[0].interfaces[0].endpoints[0].pack()
        for e in self.configurations[0].interfaces[0].endpoints:
            _str += e.pack()
        self.all_configurations = _str


    def send_usb_req(self, usb_res, usb_len, status=0, ep=0, start_frame=0, packets=0, seqnum=None, 
                     direction=0):
        rsp = USBIPRETSubmit(command=0x3,
                             seqnum=seqnum,
                             devid=0,
                             direction=direction,
                             ep=ep,
                             status=status,
                             actual_length=usb_len,
                             start_frame=start_frame,
                             number_of_packets=packets,
                             error_count=0,
                             interval=0x0,
                             padding=0,
                             data_frame=usb_res).pack()
        dump_bytes(list(rsp), colour=bcolors.FAIL, component='USBDevice(response)', msg='response bytes:')
        assert self.connection is not None, "connection socket lost"
        self.connection.sendall(rsp)

    def handle_get_descriptor(self, control_req, usb_req):
        handled = False
        # wValue (little-endian) = (descriptor_type << 8) | descriptor_index
        desc_type = control_req.wValue >> 8
        desc_index = control_req.wValue & 0xFF
        if desc_type == 0x01:  # Device descriptor
            handled = True
            ret=DeviceDescriptor(bDeviceClass=self.bDeviceClass,
                                 bDeviceSubClass=self.bDeviceSubClass,
                                 bDeviceProtocol=self.bDeviceProtocol,
                                 bMaxPacketSize0=8,
                                 idVendor=self.vendorID,
                                 idProduct=self.productID,
                                 bcdDevice=self.bcdDevice,
                                 iManufacturer=1 if self.manufacturer_string else 0,
                                 iProduct=2 if self.product_string else 0,
                                 iSerialNumber=3 if self.serial_string else 0,
                                 bNumConfigurations=1).pack()
            self.send_usb_req(ret, len(ret), seqnum=usb_req.seqnum)
        elif desc_type == 0x03:  # String descriptor
            handled = True
            ret = self._usb_string_descriptor_by_index(desc_index)
            if ret:
                ret = ret[:control_req.wLength]
            self.send_usb_req(ret, len(ret), seqnum=usb_req.seqnum)
        elif desc_type == 0x02:  # Configuration descriptor
            handled = True
            ret= self.all_configurations[:control_req.wLength]
            #print(ret)
            self.send_usb_req(ret, len(ret), seqnum=usb_req.seqnum)
        elif desc_type == 0x06:  # Device qualifier descriptor
            handled = True
            ret = DeviceQualifierDescriptor(
                bDeviceClass=self.bDeviceClass,
                bDeviceSubClass=self.bDeviceSubClass,
                bDeviceProtocol=self.bDeviceProtocol,
                bMaxPacketSize0=8,
                bNumConfigurations=self.bNumConfigurations,
            ).pack()[:control_req.wLength]
            self.send_usb_req(ret, len(ret), seqnum=usb_req.seqnum)
        return handled


    def handle_set_configuration(self, control_req, usb_req):
        handled = True
        self.send_usb_req(b'', 0, seqnum=usb_req.seqnum)
        return handled

    def handle_usb_control(self, usb_req):
        control_req = StandardDeviceRequest()
        control_req.unpack(usb_req.setup.to_bytes(8, 'big'))
        handled = False
        print('[' + bcolors.OKBLUE + 'USBDevice(handle_usb_control)' + bcolors.ENDC + "] UC Request Type" + \
                " {}; UC Request {}; UC Value  {}; UCIndex  {}; UC Length {}".format(
                control_req.bmRequestType, control_req.bRequest, control_req.wValue, control_req.wIndex,
                control_req.wLength))
        if control_req.bmRequestType == 0x80: # Host Request
            if control_req.bRequest == 0x06: # Get Descriptor
                handled = self.handle_get_descriptor(control_req, usb_req)
            if control_req.bRequest == 0x00: # Get STATUS
                self.send_usb_req(b"\x01\x00", 2, seqnum=usb_req.seqnum);
                handled = True

        if control_req.bmRequestType == 0x00: # Host Request
            if control_req.bRequest == 0x09: # Set Configuration
                handled = self.handle_set_configuration(control_req, usb_req)
        if not handled:
            self.handle_unknown_control(control_req, usb_req)

    def handle_usb_request(self, usb_req):
        try:
            if usb_req.ep == 0:
                print('[' + bcolors.OKBLUE + 'USBDevice(handle_usb_request)' + bcolors.ENDC + '] Control request')
                self.handle_usb_control(usb_req)
            else:
                print('[' + bcolors.OKBLUE + 'USBDevice(handle_usb_request)' + bcolors.ENDC + \
                        '] Data request for ep {}'.format(usb_req.ep))
                self.handle_data(usb_req)
        except Exception as e:
            print(e)
            traceback.print_exc()
            raise e


# ============================================================================
# FIDO2 HID Descriptors and Configuration
# ============================================================================

class CTAP2HIDClass(USBDescriptor):
    """HID Class Descriptor for FIDO2 Authenticator"""
    _fields_ = [
        ('bLength', 'B', 9),
        ('bDescriptorType', 'B', 0x21),  # HID
        ('bcdHID', 'H'),
        ('bCountryCode', 'B'),
        ('bNumDescriptors', 'B'),
        ('bDescriptprType2', 'B'),
        ('wDescriptionLength', 'H'),
    ]


# FIDO2 HID Report Descriptor configuration
fido2_hid_class = CTAP2HIDClass(
    bcdHID=0x0100,  # HID version number
    bCountryCode=0x0,
    bNumDescriptors=0x1,
    bDescriptprType2=0x22,  # Report
    wDescriptionLength=34  # report descriptor length (see generate_fido2_report)
)

# Interface Descriptor for FIDO2
fido2_interface_d = InterfaceDescriptor(
    bAlternateSetting=0,
    bNumEndpoints=2,
    bInterfaceClass=3,  # class HID
    bInterfaceSubClass=0,  # no interface subclass
    bInterfaceProtocol=0,  # no interface protocol
    iInterface=0
)

# Endpoint 1: HOST OUT / USB IN (0x04)
fido2_end_point_one = EndPoint(
    bEndpointAddress=0x04,
    bmAttributes=0x3,  # Interrupt transfer
    wMaxPacketSize=64,  # 64-byte packet max
    bInterval=5  # Poll every 5 millisecond
)

# Endpoint 2: HOST IN / USB OUT (0x8E)
fido2_end_point_two = EndPoint(
    bEndpointAddress=0x8E,
    bmAttributes=0x3,  # Interrupt transfer
    wMaxPacketSize=64,  # 64-byte packet max
    bInterval=5  # Poll every 5 millisecond
)

fido2_interface_d.descriptions = [fido2_hid_class]  # pyright: ignore
fido2_interface_d.endpoints = [fido2_end_point_two, fido2_end_point_one]  # pyright: ignore
# Device Configuration
fido2_configuration = DeviceConfigurations(
    wTotalLength=41,  # config(9)+interface(9)+HID(9)+2 endpoints(7+7)
    bNumInterfaces=0x1,
    bConfigurationValue=0x1,
    iConfiguration=0x0,  # No string
    bmAttributes=0x80,  # valid self powered
    bMaxPower=50  # 50 mah current
)
fido2_configuration.interfaces = [fido2_interface_d]  # pyright: ignore


# ============================================================================
# CTAP2 USB/IP Device Implementation
# ============================================================================

class CTAP2USBIPDevice(USBDevice):
    """USB/IP FIDO2 Authenticator Device
    
    This class implements a FIDO2 authenticator over USB/IP transport.
    It handles:
    - USB device descriptors and configuration
    - CTAPHID protocol (framing, channel management)
    - Integration with AuthenticatorAPI for CTAP2 commands
    """
    
    # USB Device Configuration
    speed = 2
    vendorID = 0x3713
    productID = 0x3713
    bcdDevice = 0x0
    bcdUSB = 0x0
    bNumConfigurations = 0x1
    bNumInterfaces = 0x1
    bConfigurationValue = 0x1
    bDeviceClass = 0x0
    bDeviceSubClass = 0x0
    bDeviceProtocol = 0x0
    configurations = [fido2_configuration]
    # Friendly names shown by `lsusb` / `usbip port` (USB string descriptors).
    manufacturer_string = "soft-fido2"
    product_string = "FIDO2 Passkey"
    serial_string = "00000001"
    
    def __init__(self):
        """Initialize USB/IP FIDO2 device"""
        USBDevice.__init__(self)
        self.start_time = datetime.datetime.now()
        # Per-device state. Class-level dictionaries survive reconnects and
        # leave completed responses attached to obsolete CIDs.
        self.cids = {}
        self.pending = []
        # Partial CTAPHID_MSG (U2F) requests that span more than one 64-byte
        # HID report. Keyed by channel id.
        self.u2f_pending = {}
        # The official CBOR engine uses this queue for CTAP responses and
        # keep-alive handling. The UHID transport initializes it in its own
        # constructor; USB/IP must initialize it explicitly as well.
        CBORCommand.set_pending(self.pending)
    
    # ========================================================================
    # USB/IP Data Handling
    # ========================================================================
    
    def handle_data(self, usb_req):
        """Handle HID interrupt endpoint data (ep=0x04, ep=0x0E)
        
        Args:
            usb_req: USB request object with endpoint and data
        """
        if usb_req.ep == 0xE:  # HOST IN endpoint
            return self._handle_outgoing(usb_req)
        else:  # HOST OUT endpoint (0x04)
            return self._handle_incoming(usb_req)
    
    def handle_unknown_control(self, control_req, usb_req):
        """Handle HID-specific control requests
        
        Args:
            control_req: Standard device request
            usb_req: USB request object
            
        Returns:
            bool: True if handled, False otherwise
        """
        handled = False
        if control_req.bmRequestType == 0x81:  # Interface request
            if control_req.bRequest == 0x6:  # Get Descriptor
                if (control_req.wValue >> 8) == 0x22:  # HID Report descriptor
                    print('[' + bcolors.OKGREEN + 'CTAP2USBIPDevice' + bcolors.ENDC + 
                          '] Send initial report ')
                    ret = self.generate_fido2_report()
                    self.send_usb_req(ret, len(ret), seqnum=usb_req.seqnum)
                    handled = True
        elif control_req.bmRequestType == 0x21:  # Host Request
            if control_req.bRequest == 0x0a:  # set idle
                print('[' + bcolors.OKGREEN + 'CTAP2USBIPDevice' + bcolors.ENDC + '] HID Idle ')
                self.send_usb_req(b'', 0, seqnum=usb_req.seqnum)
                handled = True
        else:
            print('[' + bcolors.FAIL + 'CTAP2USBIPDevice' + bcolors.ENDC + 
                  '] Unknown control [{}] '.format(
                      ', '.join(hex(x) for x in list(usb_req.setup.to_bytes(8, 'big')))))
            print('[' + bcolors.FAIL + 'CTAP2USBIPDevice' + bcolors.ENDC + 
                  '] Unknown flags [{}] '.format(
                      ', '.join(hex(x) for x in list(usb_req.flags.to_bytes(8, 'big')))))
            print('[' + bcolors.FAIL + 'CTAP2USBIPDevice' + bcolors.ENDC + 
                  '] Unknown data [{}] '.format(
                      ', '.join(hex(x) for x in list(usb_req.data_frame))))
            self.send_usb_req(b"\x01\x00", 2, seqnum=usb_req.seqnum)
        return handled
    
    # ========================================================================
    # CTAPHID Frame Handling
    # ========================================================================
    
    def _handle_incoming(self, usb_req):
        """Process incoming CTAPHID frames from HOST OUT endpoint
        
        Args:
            usb_req: USB request with CTAPHID frame data
        """
        log = logging.getLogger("soft_fido2")
        log.info("INCOMING frame ep=%s: %s", usb_req.ep,
                 usb_req.data_frame.hex())
        if len(self.pending) == 0:
            colour_print(colour=bcolors.FAIL, component="CTAP2USBIPDevice._handle_incoming",
                        msg="No pending request to respond with :(")
        else:  # Reply to HOST Out endpoint with empty frame then process command
            self.send_usb_req('', 64, ep=0, start_frame=0xFFFFFFFF, seqnum=usb_req.seqnum)
        
        # Parse CTAPHID frame
        cid = usb_req.data_frame[0:4]
        cmd = usb_req.data_frame[4:5]
        colour_print(colour=bcolors.OKGREEN, component='CTAP2USBIPDevice._handle_incoming',
                    msg='CID: {}; command: {}'.format(self._bytes_to_str(cid), 
                                                      self._bytes_to_str(cmd)))
        
        if (int.from_bytes(cmd, 'big') & 0x80) > 0:  # Command frame (bit 7 set)
            colour_print(colour=bcolors.FAIL, component='CTAP2USBIPDevice._handle_incoming',
                        msg='bit 8 set we got a command msg')
            return self._handle_incoming_cmd(cmd, usb_req)
        else:  # Sequence frame
            colour_print(colour=bcolors.OKPURPLE, component='CTAP2USBIPDevice._handle_incoming',
                        msg='Recieved a sequence segment, appending it to the current msg context')
            return self._handle_incoming_sequence(cid, usb_req)
    
    def _handle_outgoing(self, usb_req):
        """Queue HOST IN requests for sending responses
        
        Args:
            usb_req: USB request to queue for response
        """
        colour_print(component='CTAP2USBIPDevice._handle_outgoing', 
                    msg='Adding request to pending')
        # Create keep-alive worker thread
        worker = self.KeepAliveWorker(usb_req, self)
        keep_alive_thread = threading.Thread(target=worker.reply_with_keepalive)
        worker.my_thread = keep_alive_thread
        self.pending.append(worker)
        
        # Check if we have a ready response to send
        for cid, context in list(self.cids.items()):
            transaction = context.get('cborCmd')
            if (transaction is not None and transaction.response_ready
                    and len(transaction.response) > 0):
                logging.getLogger("soft_fido2").info(
                    "OUTGOING: sending next segment cid=%s remaining=%d",
                    self._bytes_to_str(cid), len(transaction.response))
                colour_print(component='CTAP2USBIPDevice._handle_outgoing',
                            msg='Using pending request to send response segment')
                self.send_response_segment(cid, transaction)
                return
        logging.getLogger("soft_fido2").info(
            "OUTGOING: no ready transaction cids=%s pending=%d",
            {self._bytes_to_str(c): (ctx.get('cborCmd') is not None,
                                     ctx.get('cborCmd') is not None and
                                     getattr(ctx.get('cborCmd'), 'response_ready', False),
                                     len(getattr(ctx.get('cborCmd'), 'response', []) or []))
             for c, ctx in self.cids.items()},
            len(self.pending))
    
    def _handle_incoming_cmd(self, cmd, usb_req):
        """Route CTAPHID commands to appropriate handlers
        
        Args:
            cmd: CTAPHID command byte
            usb_req: USB request object
        """
        ctapCmd = int.from_bytes(cmd, 'big') & 0x7F
        colour_print(colour=bcolors.OKGREEN, component='CTAP2USBIPDevice._handle_incoming_cmd',
                    msg='recieved command {}'.format(ctapCmd))
        return {
            1: self.ctaphid_ping,
            3: self.ctaphid_msg,
            6: self.ctaphid_init,
            16: self.ctaphid_cbor,
            17: self.ctaphid_cancel,
            59: self.ctaphid_keepalive,
            63: self.ctaphid_error,
        }.get(ctapCmd, self.ctaphid_unknown)(usb_req)
    
    def _handle_incoming_sequence(self, cid, usb_req):
        """Handle CTAPHID continuation packets"""
        seqNum = int.from_bytes(usb_req.data_frame[4:5], 'big')

        # A U2F (CTAPHID_MSG) request may span frames; finish it first.
        if cid in self.u2f_pending:
            entry = self.u2f_pending[cid]
            entry['data'] += usb_req.data_frame[5:5 + 59]
            if len(entry['data']) >= entry['bcnt']:
                apdu = bytes(entry['data'][:entry['bcnt']])
                cmd = entry['cmd']
                del self.u2f_pending[cid]
                self._dispatch_u2f(cid, cmd, apdu)
            return

        context = self.cids.get(cid)
        if context is None:
            colour_print(colour=bcolors.FAIL,
                        component='CTAP2USBIPDevice._handle_incoming_sequence',
                        msg='CID not found')
            return
            
        transaction = context.get("cborCmd")
        if transaction is None:
            colour_print(colour=bcolors.FAIL,
                        component='CTAP2USBIPDevice._handle_incoming_sequence',
                        msg='No transaction for CID')
            return
        
        # Let CBORCommand handle buffering
        transaction.append_segment(usb_req.data_frame[5:], seq_num=seqNum)
        
        if transaction.response_ready:
            self.send_response_segment(cid, transaction)
    
    # ========================================================================
    # CTAPHID Protocol Handlers
    # ========================================================================
    
    def ctaphid_init(self, usb_req):
        """CTAPHID_INIT: Assign new channel ID
        
        Args:
            usb_req: USB request with INIT command
        """
        
        cid = usb_req.data_frame[0:4]
        cmd = usb_req.data_frame[4:5]
        bcnt = usb_req.data_frame[5:7]
        nonce = usb_req.data_frame[7:15]
        assignedCID = bytes([0, random.randint(0, 255), 0, random.randint(0, 255)])
        colour_print(colour=bcolors.OKGREEN, component='CTAP2USBIPDevice.ctaphid_init',
                    msg='Assigning a new CID to {}'.format(self._bytes_to_str(assignedCID)))
        
        data = nonce + assignedCID
        # protocol == 2; major version == 5; minor version = 1; build version = 2; capabilities
        for i in [2, 5, 1, 2, 0x04 | 0x08]:
            data += bytes([i])
        dump_bytes(data, colour=bcolors.OKGREEN, component='CTAP2USBIPDevice.ctaphid_init',
                  msg='Response data')
        data += b'\x00' * (57 - len(data))  # Pad to 57 bytes (64 - 4 CID - 1 cmd - 2 bcnt)
        
        # Register the new channel without retaining this one-shot INIT
        # response. Retaining it makes later host-IN polls resend the INIT
        # transaction and starves getInfo/clientPIN responses on the new CID.
        self.cids[assignedCID] = {'cborCmd': None}
        init_cmd = CBORCommand(cid, None, skip_init=True)
        init_cmd.response = list(data)
        init_cmd.ctaphid_cmd = int.from_bytes(cmd, 'big')
        init_cmd.bcnt = 17
        self.send_response_segment(cid, init_cmd)
    
    def ctaphid_cbor(self, usb_req):
        """CTAPHID_CBOR: Process CTAP2 commands
        
        Args:
            usb_req: USB request with CBOR command
        """
        
        cid = usb_req.data_frame[0:4]
        colour_print(colour=bcolors.OKGREEN, component='CTAP2USBIPDevice.ctaphid_cbor',
                    msg='CBOR message recieved on channel {}'.format(self._bytes_to_str(cid)))
        cmd = usb_req.data_frame[4:5]
        bcnt = usb_req.data_frame[5:7]
        ctap_cmd = usb_req.data_frame[7:8]
        logging.getLogger("soft_fido2").info(
            "ctaphid_cbor RAW frame: cid=%s cmd=0x%02x bcnt=%d ctap_cmd=0x%02x "
            "frame=%s",
            self._bytes_to_str(cid), cmd[0], int.from_bytes(bcnt, 'big'),
            ctap_cmd[0], usb_req.data_frame.hex())
        cbor_data = usb_req.data_frame[8: 7 + int.from_bytes(bcnt, 'big')]
        colour_print(colour=bcolors.OKGREEN, component='CTAP2USBIPDevice.ctaphid_cbor',
                    msg='CBOR msg frame cmd: {}; bcnt: {}'.format(self._bytes_to_str(ctap_cmd),
                                                                  self._bytes_to_str(bcnt)))
        dump_bytes(cbor_data, colour=bcolors.OKGREEN, component='CTAP2USBIPDevice.ctaphid_cbor',
                  msg='CBOR encoded bytes: ')
        
        cbor_cmd = CBORCommand(cid, usb_req.data_frame[5:])
        cbor_cmd.ctaphid_cmd = int.from_bytes(cmd, 'big')
        self.cids[cid]['cborCmd'] = cbor_cmd
        
        if cbor_cmd.response_ready:  # Can respond immediately
            dump_bytes(self.cids[cid]['cborCmd'].response, colour=bcolors.OKGREEN,
                      component='CTAP2USBIPDevice.ctaphid_cbor', msg='CBOR response: ')
            return self.send_response_segment(cid, self.cids[cid]['cborCmd'])
        else:
            colour_print(colour=bcolors.OKYELLOW, component='CTAP2USBIPDevice.ctaphid_cbor',
                        msg="Waiting for rest of command to arrive . . .")
            return
    
    def ctaphid_msg(self, usb_req):
        """CTAPHID_MSG: Handle U2F legacy commands
        
        Args:
            usb_req: USB request with U2F message
        """
        
        cid = usb_req.data_frame[0:4]
        if cid not in self.cids:
            colour_print(colour=bcolors.FAIL, component='CTAP2USBIPDevice.ctaphid_msg',
                        msg='Unknown CID {}'.format(cid))
        cmd = usb_req.data_frame[4:5]
        bcnt = int.from_bytes(usb_req.data_frame[5:7], 'big')
        # A single CTAPHID frame carries at most 57 payload bytes after the
        # 7-byte header (cid|cmd|bcnt). A U2F probe can exceed this and must
        # be reassembled across continuation frames.
        first = usb_req.data_frame[7:7 + 57]
        if bcnt <= len(first):
            self._dispatch_u2f(cid, cmd, first[:bcnt])
            return
        self.u2f_pending[cid] = {'bcnt': bcnt, 'cmd': cmd,
                                 'data': bytearray(first)}
        colour_print(colour=bcolors.OKYELLOW, component='CTAP2USBIPDevice.ctaphid_msg',
                    msg='U2F message spans frames (bcnt={}); waiting for continuation'.format(bcnt))

    def _dispatch_u2f(self, cid, cmd, apdu):
        """Route a complete U2F APDU to the official CTAP engine."""
        logging.getLogger("soft_fido2").info(
            "U2F dispatch: cid=%s cmd=0x%02x apdu_len=%d apdu=%s",
            self._bytes_to_str(cid), cmd[0], len(apdu), apdu.hex())
        # Keep the official implementation's complete U2F handling, including
        # the REGISTER/AUTHENTICATE probe Chromium performs before WebAuthn.
        rsp = CBORCommand(cid, None, skip_init=True)._u2f_req(
            cid, int.from_bytes(cmd, 'big'), apdu)
        self.cids[cid]['cborCmd'] = rsp
        logging.getLogger("soft_fido2").info(
            "U2F response ready: cid=%s rsp_len=%d rsp=%s pending=%d",
            self._bytes_to_str(cid), len(rsp.response),
            bytes(rsp.response).hex(), len(self.pending))
        self.send_response_segment(cid, rsp)
    
    def ctaphid_ping(self, usb_req):
        """CTAPHID_PING: Echo data back"""
        return
    
    def ctaphid_cancel(self, usb_req):
        """CTAPHID_CANCEL: Cancel pending request"""
        return
    
    def ctaphid_keepalive(self, usb_req):
        """CTAPHID_KEEPALIVE: Keep-alive message"""
        return
    
    def ctaphid_error(self, usb_req):
        """CTAPHID_ERROR: Error response"""
        return
    
    def ctaphid_unknown(self, usb_req):
        """Handle unknown CTAPHID commands"""
        colour_print(colour=bcolors.FAIL, component='CTAP2USBIPDevice.ctaphid_unknown',
                    msg='Unkown request recieved')
        self.send_usb_req(b'', 0, ep=usb_req.ep, seqnum=usb_req.seqnum)
    
    # ========================================================================
    # Response Management
    # ========================================================================
    
    def send_response_segment(self, cid, cbor_cmd):
        """Send CTAPHID response frames
        
        Args:
            cid: Channel ID
            cbor_cmd: CBORCommand with response data
        """
        # CTAPHIDInitPkt and CTAPHIDSeqPkt imported at module top from ctaphid_protocol
        
        if len(self.pending) == 0:
            colour_print(colour=bcolors.FAIL, component='send_response_segment',
                        msg='No pending transactions to use :(')
            return
        
        # Take control of the next pending request
        self.pending[0].stop = True
        if self.pending[0].my_thread is not None and self.pending[0].my_thread.is_alive():
            self.pending[0].my_thread.join(1/1000)
        if self.pending[0].my_thread.is_alive():
            colour_print(colour=bcolors.FAIL, component='send_response_segment',
                        msg='Could not kill keepalive thread')
            return
        
        rsp_data = None
        if cbor_cmd.response_segment == 0:  # Send init packet
            data, _ = cbor_cmd.get_rsp_seg(57)
            rsp_data = CTAPHIDInitPkt(cid=int.from_bytes(cid, 'big'),
                                     cmd=cbor_cmd.ctaphid_cmd,
                                     bcnt=cbor_cmd.bcnt,
                                     data=bytes(data)).pack()
        else:  # Send continuation sequence packet
            data, seq_num = cbor_cmd.get_rsp_seg(59)
            colour_print(colour=bcolors.WARNING, component='send_response_segment',
                        msg='Sequence number {}'.format(seq_num))
            rsp_data = CTAPHIDSeqPkt(cid=int.from_bytes(cid, 'big'),
                                    seq=seq_num,
                                    data=bytes(data)).pack()
        
        colour_print(colour=bcolors.WARNING, component='send_response_segment',
                    msg='pad with {} 0 bytes'.format(64 - len(rsp_data)))
        rsp_data += b'\00' * (64 - len(rsp_data))  # Pad to 64 bytes
        
        dump_bytes(rsp_data, colour=bcolors.OKGREEN, component='CTAP2USBIPDevice.send_response_segment',
                  msg='Packed response: ')
        self.send_usb_req(rsp_data, len(rsp_data), start_frame=0xFFFFFFFF, packets=0,
                         ep=0, direction=0, seqnum=self.pending[0].req.seqnum)
        del self.pending[0]
        
        # If no response buffer left, remove transaction from context
        # Don't do this for the broadcast channel
        if len(cbor_cmd.response) == 0 and cid != b'\xff\xff\xff\xff':
            context = self.cids.get(cid)
            if context is not None and context.get('cborCmd') is cbor_cmd:
                del self.cids[cid]['cborCmd']
        return
    
    def unlink(self, usb_req):
        """Unlink a pending request
        
        Args:
            usb_req: USB request to unlink
            
        Returns:
            bool: True if unlinked, False otherwise
        """
        index = None
        for i, worker in enumerate(self.pending):
            if worker.req.seqnum == usb_req.unlink_seqnum:
                index = i
        if index is not None:
            del self.pending[index]
            colour_print(component='CTAP2USBIPDevice.unlink',
                        msg='unlinked request {}'.format(usb_req.unlink_seqnum))
            return True
        return False
    
    # ========================================================================
    # Keep-Alive Mechanism
    # ========================================================================
    
    class KeepAliveWorker(object):
        """Thread to send keep-alive if response takes >50ms"""
        
        def __init__(self, req, hid):
            self.stop = False
            self.my_thread: threading.Thread | None = None
            self.req = req
            self.hid = hid
            self.start = None
        
        def reply_with_keepalive(self):
            """Send keep-alive messages if processing takes too long"""
            start = round(time.time() * 1000)
            while not self.stop:
                now = round(time.time() * 1000)
                wait_time = now - start
                if (now >= start + 450) and not self.stop:  # If we get to 45ms, send heartbeat
                    colour_print(colour=bcolors.FAIL, component='KeepAliveWorker.reply_with_keepalive',
                                msg='Thread reached timeout of {} ms before response buffer was recieved . . . sending heartbeat response'.format(wait_time))
                    # Reply with keep alive after 50ms (45ms gives tolerance)
                    # Status is always still processing
                    rsp = b'\x3B\x01\x01'
                    self.hid.send_usb_req(rsp, len(rsp), start_frame=0xFFFFFFFF, packets=0, ep=0,
                                         direction=0, seqnum=self.req.seqnum)
                    self.stop = True
                    # Remove transaction from pending list
                    for idx, txn in enumerate(self.hid.pending):
                        if txn.req is not None and txn.req.seqnum is not None and txn.req.seqnum == self.req.seqnum:
                            del self.hid.pending[idx]
                    return
                time.sleep(5/1000)  # sleep for 5 ms
    
    # ========================================================================
    # HID Descriptor Generation
    # ========================================================================
    
    def generate_fido2_report(self):
        """Generate HID Report Descriptor for FIDO2
        
        Returns:
            bytes: HID report descriptor
        """
        arr = [0x06, 0xd0, 0xf1,        # USAGE_PAGE (FIDO Alliance)
               0x09, 0x01,              # USAGE (CTAPHID)
               0xa1, 0x01,              # HID_Collection(HID_Application)
               0x09, 0x20,              # USAGE (Input Report Data)
               0x15, 0x00,              # LOGICAL_MINIMUM (0)
               0x26, 0xff, 0x00,        # LOGICAL_MAXIMUM (255)
               0x75, 0x08,              # REPORT_SIZE (8)
               0x95, 0x40,              # REPORT_COUNT (64)
               0x81, 0x02,              # INPUT (Data,Var,Abs)
               0x09, 0x21,              # USAGE(Output Report Data)
               0x15, 0x00,              # LOGICAL_MINIMUM (0)
               0x26, 0xff, 0x00,        # LOGICAL_MAXIMUM (255)
               0x75, 0x08,              # REPORT_SIZE (8)
               0x95, 0x40,              # REPORT_COUNT (64)
               0x91, 0x02,              # OUTPUT (Data,Var,Abs)
               0xc0]                    # End Collection
        return bytes(arr)
    
    # ========================================================================
    # Utility Methods
    # ========================================================================
    
    def _bytes_to_str(self, b):
        """Convert bytes to hex string
        
        Args:
            b: bytes to convert
            
        Returns:
            str: Hex string representation
        """
        return ''.join("%02X" % x for x in b)


class USBIPTCPServer(socketserver.ThreadingTCPServer):
    """ThreadingTCPServer with a typed reference back to the owning USBContainer."""
    usbcontainer: Optional["USBContainer"] = None


class USBContainer:
    usb_devices = {}
    attached_devices = {}
    devices_count = 0
    server: Optional[USBIPTCPServer] = None

    def __init__(self):
        self.shutdown_event = threading.Event()

    def add_usb_device(self, usb_device):
        self.devices_count += 1
        busID = '1-1.' + str(self.devices_count)
        self.usb_devices[busID] = usb_device
        self.attached_devices[busID] = False

    def remove_usb_device(self, usb_device):
        for busid, dev in self.usb_devices.items():
            if dev == usb_device:
                del self.attached_devices[busid]
                del self.usb_devices[busid]
                break
        self.devices_count -= 1

    def detach_all(self):
        self.attached_devices = {}
        self.usb_devices = {}
        self.devices_count = 0

    def handle_attach(self, busid) -> OPREPImport:
        if self.usb_devices[busid] is not None:
            busnum = int(busid[4:])
            return OPREPImport(base=USBIPHeader(command=3, status=0),
                               usbPath='/sys/devices/pci0000:00/0000:00:01.2/usb1/' + busid,
                               busID=busid,
                               busnum=busnum,
                               devnum=2,
                               speed=2,
                               idVendor=self.usb_devices[busid].vendorID,
                               idProduct=self.usb_devices[busid].productID,
                               bcdDevice=self.usb_devices[busid].bcdDevice,
                               bDeviceClass=self.usb_devices[busid].bDeviceClass,
                               bDeviceSubClass=self.usb_devices[busid].bDeviceSubClass,
                               bDeviceProtocol=self.usb_devices[busid].bDeviceProtocol,
                               bNumConfigurations=self.usb_devices[busid].bNumConfigurations,
                               bConfigurationValue=self.usb_devices[busid].bConfigurationValue,
                               bNumInterfaces=self.usb_devices[busid].bNumInterfaces)
        raise KeyError(f"No USB device registered for busid '{busid}'")

    def handle_device_list(self):
        devices = {}

        i = 0
        for busid, usb_dev in self.usb_devices.items():
            i += 1
            devices['device' + str(i)] = [USBIPDevice(), USBIPDevice(
                usbPath='/sys/devices/pci0000:00/0000:00:01.2/usb1/' + busid,
                busID=busid,
                busnum=i,
                devnum=2,
                speed=2,
                idVendor=self.usb_devices[busid].vendorID,
                idProduct=self.usb_devices[busid].productID,
                bcdDevice=self.usb_devices[busid].bcdDevice,
                bDeviceClass=self.usb_devices[busid].bDeviceClass,
                bDeviceSubClass=self.usb_devices[busid].bDeviceSubClass,
                bDeviceProtocol=self.usb_devices[busid].bDeviceProtocol,
                bNumConfigurations=self.usb_devices[busid].bNumConfigurations,
                bConfigurationValue=self.usb_devices[busid].bConfigurationValue,
                bNumInterfaces=self.usb_devices[busid].bNumInterfaces,
                interfaces=USBInterface(bInterfaceClass=self.usb_devices[busid].configurations[0].interfaces[0].bInterfaceClass,
                                        bInterfaceSubClass=self.usb_devices[busid].configurations[0].interfaces[0].bInterfaceSubClass,
                                        bInterfaceProtocol=self.usb_devices[busid].configurations[0].interfaces[0].bInterfaceProtocol)
            )]

        return OPREPDevList(devices, len(self.usb_devices))


    def run(self, ip='0.0.0.0', port=3240):
        colour_print(colour=bcolors.OKBLUE, component='USBIP', msg='Starting server')
        socketserver.TCPServer.allow_reuse_address = True
        self.server = USBIPTCPServer((ip, port), USBIPConnection)
        self.server.usbcontainer = self
        
        # Set up signal handlers for graceful shutdown (must be in main thread)
        def signal_handler(signum, frame):
            colour_print(colour=bcolors.WARNING, component='USBIP', msg='Received signal {}, shutting down...'.format(signum))
            # Force immediate exit without cleanup to avoid hanging
            import os
            os._exit(0)
        
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)
        
        try:
            self.server.serve_forever()
        except KeyboardInterrupt:
            # Fallback in case signal handler doesn't work
            colour_print(colour=bcolors.WARNING, component='USBIP', msg='KeyboardInterrupt received, shutting down...')
            import os
            os._exit(0)
        finally:
            colour_print(colour=bcolors.OKBLUE, component='USBIP', msg='Server cleanup complete')


class USBIPConnection(socketserver.BaseRequestHandler):
    attached = False
    attachedBusID = ''

    def __init__(self, request=None, client_address=None, server=None):
        super().__init__(request=request, client_address=client_address, server=server)

    def _recv_exact(self, n):
        """Read exactly n bytes, looping over partial TCP segments.

        Returns b'' if the peer closed before n bytes arrived; raises
        socket.timeout if the (1s) socket timeout elapses mid-read.
        """
        buf = b''
        while len(buf) < n:
            chunk = self.request.recv(n - len(buf))
            if not chunk:
                return buf
            buf += chunk
        return buf

    def handle(self):
        endpoint_requests = {}
        colour_print(colour=bcolors.OKBLUE, component='USBIP', msg='New connection from {}'.format(self.client_address))
        req = USBIPHeader()
        # Narrow Optional type: usbcontainer is always set before any connection is accepted
        assert isinstance(self.server, USBIPTCPServer)  # narrow the inherited BaseServer type
        assert self.server.usbcontainer is not None
        usbcontainer = self.server.usbcontainer
        # Set socket timeout to allow checking shutdown event
        self.request.settimeout(1.0)
        while not usbcontainer.shutdown_event.is_set():
            if not self.attached:
                try:
                    data = self._recv_exact(8)
                    if not data:
                        break
                    if len(data) < 8:
                        # peer closed mid-header
                        break
                except:
                    # Timeout or other error, check shutdown event and continue
                    continue
                req.unpack(data)
                colour_print(colour=bcolors.OKBLUE, component='USBIP', msg='Header packet is valid')
                colour_print(colour=bcolors.OKBLUE, component='USBIP', msg='Command is {}'.format(hex(req.command or 0)))
                if req.command == 0x8005:
                    colour_print(colour=bcolors.OKBLUE, component='USBIP', msg='Querying device list')
                    self.request.sendall(usbcontainer.handle_device_list().pack())
                elif req.command == 0x8003:
                    try:
                        busid = self._recv_exact(5).strip()  # receive bus id
                        self._recv_exact(27)
                    except Exception:
                        colour_print(colour=bcolors.WARNING, component='USBIP',
                                     msg='incomplete attach request, continuing')
                        continue
                    colour_print(colour=bcolors.OKBLUE, component='USBIP',
                                 msg='Attaching to device with busid [{}]'.format(busid.decode()))
                    self.request.sendall(usbcontainer.handle_attach(busid.decode()).pack())
                    self.attached = True
                    self.attachedBusID = busid.decode()
                    colour_print(colour=bcolors.OKBLUE, component='USBIP', msg='attached')

            else:
                #print(usbcontainer.usb_devices)
                if (not self.attachedBusID in usbcontainer.usb_devices):
                    colour_print(colour=bcolors.WARNING, component='USBIP', msg='closing')
                    self.request.close()
                    break
                else:
                    try:
                        command = self._recv_exact(4)
                        if not command:
                            break
                        if len(command) < 4:
                            break
                        colour_print(component='USB/IP', msg='Command received')
                        dump_bytes(command, msg='USB/IP command bytes recieved:')
                        cmdVal = struct.unpack('>I', command)[0]
                    except:
                        # Timeout or other error, check shutdown event and continue
                        continue
                    '''
                    if (cmdVal == 0x00000003):
                        cmd = USBIPCMDUnlink()
                        data = self.request.recv(cmd.size())
                        cmd.unpack(data)
                        colour_print(component='USBIP', msg='Detaching device with seqnum {}'.format(cmd.seqnum))
                        # We probably don't even need to handle that, the windows client doesn't even send this packet
                    '''
                    if (cmdVal == 0x00000001):
                        cmd = USBIPCMDSubmit()
                        try:
                            data = self._recv_exact(cmd.size() - 4)
                        except Exception:
                            colour_print(colour=bcolors.WARNING, component='USBIP',
                                         msg='incomplete submit request, continuing')
                            continue
                        cmd.unpack(command + data)
                        msg = 'USB/IP Command::\n\tseqnum: {}; devid: {};\n\tdirection: {}; ep: {};\n\tflags: {};'\
                                'transfer buffer: {};\n\tstart_frame: {}; no. of pkts: {}; '\
                                '\n\tinterval: {}; setup: {}'.format(
                            cmd.seqnum,cmd.devid,cmd.direction,cmd.ep,cmd.transfer_flags,cmd.transfer_buffer_length,
                            cmd.start_frame,cmd.number_of_packets,cmd.interval,list((cmd.setup or 0).to_bytes(8, 'big')))
                        colour_print(colour=bcolors.OKBLUE, component='USBIPConnection.handle', msg=msg)
                        if endpoint_requests.get(cmd.ep) == None:
                            endpoint_requests[cmd.ep] = 1
                        else:
                            endpoint_requests[cmd.ep] = (endpoint_requests.get(cmd.ep) or 0) + 1
                        msg = "Endpoint requests: {}".format( endpoint_requests)
                        colour_print(component='USBIPConnection.handle', msg=msg)
                        data_frame = b''
                        if cmd.start_frame == 0xFFFFFFFF and cmd.transfer_flags == 0x0:
                            colour_print(colour=bcolors.OKYELLOW, component='USBIPConnection.handle', msg='CTAPHID:: '\
                                    'FIDO2 Authenticator recieved start_frame, reading rest of data maybe . . .')
                            try:
                                data_frame = self._recv_exact(cmd.transfer_buffer_length)
                            except Exception:
                                colour_print(colour=bcolors.WARNING, component='USBIP',
                                             msg='incomplete data frame, continuing')
                                continue
                            dump_bytes(data_frame, component='USBIPConnection.handle', msg='data bytes recieved:')
                        usb_req = USBRequest(seqnum=cmd.seqnum,
                                             devid=cmd.devid,
                                             direction=cmd.direction,
                                             ep=cmd.ep,
                                             flags=cmd.transfer_flags,
                                             number_of_packets=cmd.number_of_packets,
                                             interval=cmd.interval,
                                             setup=cmd.setup,
                                             cmd_frame=cmd.pack(),
                                             data_frame=data_frame)
                        dump_bytes(list((usb_req.setup or 0).to_bytes(8, 'big')), colour=bcolors.FAIL,
                                   component='USBDevice(send_usb_req)', msg='setup bytes:')
                        dump_bytes(list(usb_req.cmd_frame), list(usb_req.data_frame), colour=bcolors.FAIL, 
                                    component='USBDevice(request)', msg='whole recieved message:')
                        usbcontainer.usb_devices[self.attachedBusID].connection = self.request
                        try:
                            usbcontainer.usb_devices[self.attachedBusID].handle_usb_request(usb_req)
                        except:
                            colour_print(colour=bcolors.FAIL, component='USBIP', 
                                         msg='Connection with client ' + str(self.client_address) + ' ended')
                            break
                    elif(cmdVal == 0x00000002):
                        cmd = USBIPUnlinkReq()
                        try:
                            data = self._recv_exact(cmd.size())
                        except Exception:
                            colour_print(colour=bcolors.WARNING, component='USBIP',
                                         msg='incomplete unlink request, continuing')
                            continue
                        cmd.unpack(data)
                        dump_bytes(command + cmd.pack(), colour=bcolors.WARNING, component='USBIP', msg='Unlink request')
                        #TODO have we actually sent a USBIP_RET_SUBMIT or not?
                        success = usbcontainer.usb_devices[self.attachedBusID].unlink(cmd)
                        status = 0x0;
                        if success == True:
                            status = 0xF
                        ret = USBIPUnlinkRet(command=0x04, seqnum=cmd.seqnum, devid=cmd.devid, direction=0, ep=cmd.ep,
                                             status=status, padding=b'\0' * 24)
                        dump_bytes(ret.pack(), colour=bcolors.WARNING, component='USBIP', msg='Unlink return')
                        self.request.sendall(ret.pack())

                    else:
                        raise Exception("Unknown USB/IP command recieved")
        self.request.close()


# ============================================================================
# Main Entry Point
# ============================================================================

if __name__ == '__main__':
    """Main entry point for USB/IP FIDO2 authenticator
    
    Usage:
        On SERVER:
            $ python -m soft_fido2.usbip_device
            # or
            $ python soft_fido2/usbip_device.py
        
        On CLIENT:
            $ sudo modprobe vhci-hcd
            $ sudo usbip list -r 127.0.0.1
            $ sudo usbip attach -r 127.0.0.1 -b 1-1.1
            $ lsusb -v -d 3713:3713
    """
    print("Starting FIDO2 USB/IP Authenticator...")
    print("Vendor ID: 0x3713, Product ID: 0x3713")
    print("Waiting for USB/IP client connection on port 3240...")
    
    # Create FIDO2 USB/IP device
    # All USB/IP protocol handling and CTAPHID frame processing is in CTAP2USBIPDevice
    usb_dev = CTAP2USBIPDevice()
    
    # Create USB container and add device
    usb_container = USBContainer()
    usb_container.add_usb_device(usb_dev)
    
    # Run the USB/IP server
    # USB frames received on usb_container will be routed to usb_dev.handle_usb_request()
    # which then calls either handle_usb_control() or handle_data() on CTAP2USBIPDevice
    try:
        usb_container.run()
    except KeyboardInterrupt:
        print("\nShutting down USB/IP authenticator...")
    except Exception as e:
        print(f"Error running USB/IP authenticator: {e}")
        import traceback
        traceback.print_exc()
        raise

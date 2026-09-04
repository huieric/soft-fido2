#!/usr/bin/env python3
# Copyright IBM Corp. 2022, 2025
# IBM Confidential
# Assisted by watsonx Code Assistant

"""Shared primitives and CTAPHID packet structures.

BaseStructure, bcolors, and colour_print live here so that both
uhid_device and usbip_device can import them without creating a
circular dependency.  This module has no imports from other soft_fido2
modules, keeping it at the bottom of the dependency graph.
"""

import struct, re, logging


# Thanks StackOverflow !
class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    OKPINK = '\033[95m'
    OKYELLOW = '\033[93m'
    OKPURPLE = '\033[35m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


# Map colour classes to log levels so failures surface as ERROR and warnings
# as WARNING, while routine protocol diagnostics stay at INFO. This keeps the
# level label honest and lets an operator filter logs at a glance.
_COLOUR_LEVELS = {
    bcolors.FAIL: logging.ERROR,
    bcolors.WARNING: logging.WARNING,
    bcolors.OKYELLOW: logging.WARNING,
    bcolors.OKGREEN: logging.INFO,
    bcolors.OKBLUE: logging.INFO,
    bcolors.OKPINK: logging.INFO,
    bcolors.OKPURPLE: logging.INFO,
}


def colour_print(colour=bcolors.OKBLUE, component='CTAPHID', msg=''):
    # Route every diagnostic through a single "soft_fido2" logger with lazy
    # %-formatting. ANSI escapes are stripped because container logs are not
    # attached to a TTY (they would show as raw control codes). The timestamp
    # and level label are added by the formatter configured in __main__.py.
    level = _COLOUR_LEVELS.get(colour, logging.INFO)
    clean = re.sub(r'\x1b\[[0-9;]*m', '', msg)
    # stacklevel=2 makes %(pathname)s/%(lineno)d point at the real call site
    # (e.g. usbip_device.py), not at this helper function.
    logging.getLogger('soft_fido2').log(level, '[%s] %s', component, clean,
                                        stacklevel=2)


class BaseStructure(object):
    """Base class for binary protocol structures.

    Subclasses declare ``_fields_`` as a list of ``(name, fmt[, default])``
    tuples. CTAPHID channel IDs and byte counts are network-order (big-endian).
    """
    _fields_ = []
    base_pack_format = '>'

    def __init__(self, **kwargs):
        self.init_from_dict(**kwargs)
        for field in self._fields_:
            if len(field) > 2:
                if not hasattr(self, field[0]):
                    setattr(self, field[0], field[2])

    def init_from_dict(self, **kwargs):
        for key, value in kwargs.items():
            setattr(self, key, value)

    def size(self):
        return struct.calcsize(self.format())

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
        return pack_format

    def pack(self):
        values = []
        for field in self._fields_:
            if isinstance(field[1], BaseStructure):
                values.append(getattr(self, field[0], field[1]).pack())
            elif re.match(r'\d*x', field[1]):
                continue  # skip padding
            else:
                if 'si' == field[1]:
                    values.append(chr(getattr(self, field[0], 0)))
                else:
                    values.append(getattr(self, field[0], 0))
        values = [bytes(v, 'utf-8') if isinstance(v, str) else v for v in values]
        return struct.pack(self.format(), *values)

    def unpack(self, buf):
        values = struct.unpack(self.format(), buf)
        i = 0
        keys_vals = {}
        for val in values:
            if '<' in self._fields_[i][1][0]:
                val = struct.unpack(
                    '<' + self._fields_[i][1][1],
                    struct.pack('>' + self._fields_[i][1][1], val)
                )[0]
            keys_vals[self._fields_[i][0]] = val
            i += 1
        self.init_from_dict(**keys_vals)


class CTAPHIDInitPkt(BaseStructure):
    """CTAPHID initialization packet (first frame of a CTAPHID message).

    Fields: channel ID (cid), command byte (cmd), total payload length (bcnt).
    A ``data`` field is appended dynamically when the caller supplies one.
    """

    _fields_ = [
        ('cid',  'I'),   # Channel identifier (4 bytes)
        ('cmd',  'B'),   # Command byte (1 byte)
        ('bcnt', 'H'),   # Byte count – total payload length (2 bytes)
    ]

    def __init__(self, **kwargs):
        if 'data' in kwargs:
            index = next(
                (i for i, f in enumerate(self._fields_) if f[0] == 'data'),
                None
            )
            data_field = ('data', '%ds' % len(kwargs['data']))
            if index is None:
                self._fields_ = list(self._fields_) + [data_field]
            else:
                self._fields_ = list(self._fields_)
                self._fields_[index] = data_field
        super().__init__(**kwargs)


class CTAPHIDSeqPkt(BaseStructure):
    """CTAPHID continuation packet (subsequent frames of a CTAPHID message).

    Fields: channel ID (cid), sequence number (seq, 0-127).
    A ``data`` field is appended dynamically when the caller supplies one.
    """

    _fields_ = [
        ('cid', 'I'),   # Channel identifier (4 bytes)
        ('seq', 'B'),   # Sequence number (1 byte, 0-127)
    ]

    def __init__(self, **kwargs):
        if 'data' in kwargs:
            index = next(
                (i for i, f in enumerate(self._fields_) if f[0] == 'data'),
                None
            )
            data_field = ('data', '%ds' % len(kwargs['data']))
            if index is None:
                self._fields_ = list(self._fields_) + [data_field]
            else:
                self._fields_ = list(self._fields_)
                self._fields_[index] = data_field
        super().__init__(**kwargs)

#!/usr/bin/env python
# Copyright (c) 2015 by Silicon Laboratories Inc. All rights reserved.
# http://developer.silabs.com/legal/version/v11/Silicon_Labs_Software_License_Agreement.txt

"""CP2112 HID to SMBus bridge interface.

This module uses the ctypes package to wrap a small set of functions from the Silicon Labs
HID to SMBus Interface library (SLABHIDtoSMBus.dll). The wrapped functions are all that are
needed to communicate with the EFM8 SMB bootloader.
"""

import ctypes as ct
import sys
import time

# Status (S0) codes
class HID_SMBUS_S0:
    IDLE = 0x00
    BUSY = 0x01
    COMPLETE = 0x02
    ERROR = 0x03

# Detailed status (S1) codes
class HID_SMBUS_S1:
    BUSY_ADDRESS_ACKED = 0x00
    BUSY_ADDRESS_NACKED = 0x01
    BUSY_READING = 0x02
    BUSY_WRITING = 0x03
    ERROR_TIMEOUT_NACK = 0x00
    ERROR_TIMEOUT_BUS_NOT_FREE = 0x01
    ERROR_ARB_LOST = 0x02
    ERROR_READ_INCOMPLETE = 0x03
    ERROR_WRITE_INCOMPLETE = 0x04
    ERROR_SUCCESS_AFTER_RETRY = 0x05

# Dictionary maps library return codes to description string
HID_SMBUS_STATUS_DESC = {
    0x00 : "HID_SMBUS_SUCCESS",
    0x01 : "HID_SMBUS_DEVICE_NOT_FOUND",
    0x02 : "HID_SMBUS_INVALID_HANDLE",
    0x03 : "HID_SMBUS_INVALID_DEVICE_OBJECT",
    0x04 : "HID_SMBUS_INVALID_PARAMETER",
    0x05 : "HID_SMBUS_INVALID_REQUEST_LENGTH",
    0x10 : "HID_SMBUS_READ_ERROR",
    0x11 : "HID_SMBUS_WRITE_ERROR",
    0x12 : "HID_SMBUS_READ_TIMED_OUT",
    0x13 : "HID_SMBUS_WRITE_TIMED_OUT",
    0x14 : "HID_SMBUS_DEVICE_IO_FAILED",
    0x15 : "HID_SMBUS_DEVICE_ACCESS_ERROR",
    0x16 : "HID_SMBUS_DEVICE_NOT_SUPPORTED",
    0xFF : "HID_SMBUS_UNKNOWN_ERROR",
}

class HidSmbusError(Exception):
    """Exception class for all HIDtoSMBus library errors.
    """
    def __init__(self, status):
        self.status = status

    def __str__(self):
        return HID_SMBUS_STATUS_DESC.get(self.status, 'SMB_STATUS_UNKNOWN: ' + hex(self.status))

def hidsmb_errcheck(result, func, args):
    """ctypes errcheck function tests return code for errors.
    """
    if result != 0:
        raise HidSmbusError(result)

# Load HID shared library using ctypes
if sys.platform == 'win32':
    _DLL = ct.windll.LoadLibrary("SLABHIDtoSMBus.dll")
elif sys.platform == 'darwin':
    _DLL = ct.cdll.LoadLibrary("libSLABHIDtoSMBus.dylib")
elif sys.platform.startswith('linux'):
    _DLL_prev = ct.CDLL("./libslabhiddevice.so.1.0", mode=ct.RTLD_GLOBAL)
    _DLL = ct.cdll.LoadLibrary('./libslabhidtosmbus.so.1.0')
else:
    raise RuntimeError("HidSmbus: Unsupported OS")

# Set return types and error check function for the wrapped library
for hidsmb_function in [
    "HidSmbus_GetNumDevices",
    "HidSmbus_Open",
    "HidSmbus_Close",
    "HidSmbus_ReadRequest",
    "HidSmbus_GetReadResponse",
    "HidSmbus_WriteRequest",
    "HidSmbus_TransferStatusRequest",
    "HidSmbus_GetTransferStatusResponse",
    "HidSmbus_SetSmbusConfig",
    "HidSmbus_AddressReadRequest"]:
    fnc = getattr(_DLL, hidsmb_function)
    fnc.restype = ct.c_int
    fnc.errcheck = hidsmb_errcheck

def port_count():
    """Return the number of attached Silicon Labs CP2112 devices.
    """
    ndev = ct.c_ulong()
    _DLL.HidSmbus_GetNumDevices(ct.byref(ndev), 0x10C4, 0xEA90)
    return ndev.value

class SmbPort(object):
    """Base class for communicating with a Silicon Labs CP2112 device.

    Creating an instance of this class automatically opens the first available
    CP2112 device.

    Args:
        bitrate: SMBus clock rate in Hz (default: 100000).

    Raises:
        HidError: If a CP2112 device is not available.
    """
    def __init__(self, bitrate=None):
        self.handle = ct.c_void_p(0)
        self.name = 'SMB:CP2112'
        if bitrate is None:
            bitrate = 50000
        if port_count():
            _DLL.HidSmbus_Open(ct.byref(self.handle), 0, 0x10C4, 0xEA90)
            _DLL.HidSmbus_SetSmbusConfig(self.handle, bitrate, 0x02, True, 500, 500, False, 1)
        else:
            raise HidSmbusError(0x01)

    def close(self):
        """Close the device handle.
        """
        _DLL.HidSmbus_Close(self.handle)

    def smb_status(self):
        """Return SMB transfer status information.

        Returns:
            Tuple(status, detailedStatus, numRetries, bytesRead)
        """
        status_0 = ct.c_byte(0)
        status_1 = ct.c_byte(0)
        tries = ct.c_ushort(0)
        count = ct.c_ushort(0)
        _DLL.HidSmbus_TransferStatusRequest(self.handle)
        _DLL.HidSmbus_GetTransferStatusResponse(self.handle, ct.byref(status_0), ct.byref(status_1), ct.byref(tries), ct.byref(count))
        return (status_0.value, status_1.value, tries.value, count.value)

    def smb_read(self, address, count=64):
        """Read a stream of bytes from a SMB slave device.

        Args:
            address: Byte-aligned slave address.
            count: Number of bytes to read (range: 1-512).

        Returns:
            Buffer with the data that was read.
        """
        _DLL.HidSmbus_ReadRequest(self.handle, (address & 0xFE), count)
        size = max(count, 64)
        buffer = []
        buf = ct.create_string_buffer(size)
        status = ct.c_byte(0)
        n_read = ct.c_byte(0)
        try:
            while n_read != 0 and self.smb_status()[0] != HID_SMBUS_S0.ERROR:
                size = max(count, 64)
                buf = ct.create_string_buffer(size)
                status = ct.c_byte(0)
                _DLL.HidSmbus_GetReadResponse(self.handle, ct.byref(status), buf, size, ct.byref(n_read))
                buffer += buf.raw[:n_read.value]
        except HidSmbusError as e:
            # Ignore timeout, return the data that was read
            if e.status != 0x12:
                raise
        return buffer

    def smb_write(self, address, buffer, count=None):
        """Write a stream of bytes to a SMB slave device.

        Args:
            address: Byte-aligned slave address.
            buffer: Buffer with data to write.
            count: Number of bytes to write (range: 1-61).
        """
        if count is None:
            count = len(buffer)
        _DLL.HidSmbus_WriteRequest(self.handle, (address & 0xFE), bytes(buffer), count)
        while self.smb_status()[0] == HID_SMBUS_S0.BUSY:
            pass

    def msa_write(self, address, offset, buffer, count=None):
        """Write a stream of bytes to a SMB slave device.

        Args:
            address: Byte-aligned slave address.
            buffer: Buffer with data to write.
            offset: Byte-aligned offset in slave address.
            count: Number of bytes to write (range: 1-61).
        """
        send = 0
        while send < count:
            buf = [offset + send]
            buf.extend(buffer[send : (send + min(0x20, (count - send)))])
            self.smb_write(address, buf, min(0x20, (count - send)) + 1)
            send += 0x20
        pass

    def msa_read(self, address, offset=0, count=64):
        """Read a stream of bytes from a SMB slave device.

        Args:
            address: Byte-aligned slave address.
            offset: Byte-aligned offset in slave address.
            count: Number of bytes to read (range: 1-512).

        Returns:
            Buffer with the data that was read.
        """
        TargetAddress = ct.c_char * 16
        off = TargetAddress(offset)
        buffer = []
        n_read = ct.c_byte(-1)
        _DLL.HidSmbus_AddressReadRequest(self.handle, (address & 0xFE), count, 1, off)
        try:
            while n_read != 0 and self.smb_status()[0] != HID_SMBUS_S0.ERROR:
                size = max(count, 64)
                buf = ct.create_string_buffer(size)
                status = ct.c_byte(0)
                _DLL.HidSmbus_GetReadResponse(self.handle, ct.byref(status), buf, size, ct.byref(n_read))
                buffer += buf.raw[:n_read.value]
        except HidSmbusError as e:
            # Ignore timeout, return the data that was read
            if e.status != 0x12:
                raise
        return buffer

    def enter_bootloader(self):
        factory_pw = [0x7B, 0x50, 0x4F, 0x45, 0x54]
        boot_pw = [0x7B, 0x62, 0x6F, 0x6F, 0x74]
        self.smb_write(0xA2, factory_pw, len(factory_pw))
        self.smb_write(0xA2, boot_pw, len(boot_pw))

    Tx = (0b1000, 0b0111, 0b0110, 0b0101)
    Rx = (0b0001, 0b0010, 0b0011, 0b0100)

    def siph_read_register(self, reg, cmd=0x1):
        page_sel = [0x7F, 0x96]
        port.smb_write(0xA0, page_sel, len(page_sel))

        buf = bytearray(b'')
        buf.extend(reg.to_bytes(2, 'big'))
        buf.extend(0x0.to_bytes(2, 'big'))
        buf.extend(cmd.to_bytes(2, 'big'))
        self.msa_write(0xA0, 0xC0, buf, len(buf))
        time.sleep(2)
        rd = self.msa_read(0xA0, 0xC0, len(buf))

        if int.from_bytes(buf[4:6], 'big') != int.from_bytes(rd[4:6], 'big'):
            print("read: reg=0x%x, val=0x%x." % (reg, int.from_bytes(rd[2:4], 'big')))
            return int.from_bytes(rd[2:4], 'big')
        else:
            return None

    def siph_write_register(self, reg, val, cmd=0x2):
        page_sel = [0x7F, 0x96]
        port.smb_write(0xA0, page_sel, len(page_sel))

        buf = bytearray(b'')
        buf.extend(reg.to_bytes(2, 'big'))
        buf.extend(val.to_bytes(2, 'big'))
        buf.extend(cmd.to_bytes(2, 'big'))
        self.msa_write(0xA0, 0xC0, buf, len(buf))
        print("write: reg=0x%x, val=0x%x." % (reg, val))
        time.sleep(2)
        rd = self.msa_read(0xA0, 0xC0, len(buf))
        print("readout: reg=0x%x, val=0x%x." % (int.from_bytes(rd[0:2], 'big'), int.from_bytes(rd[2:4], 'big')))

    def siph_read_tx_register(self, reg, lane=0):
        return self.siph_read_register(self.Tx[lane] << 6 | reg)

    def siph_write_tx_register(self, reg, val, lane=0):
        self.siph_write_register(self.Tx[lane] << 6 | reg, val)

    def siph_read_rx_register(self, reg, lane=0):
        return self.siph_read_register(self.Rx[lane] << 6 | reg)

    def siph_write_rx_register(self, reg, val, lane=0):
        self.siph_write_register(self.Rx[lane] << 6 | reg, val)

    def siph_enter_mission_mode(self, lane=0):
        """
        """
        print('lane: %d' % (lane))
        print('Set Mission Mode')
        txcdr0 = self.siph_read_tx_register(0x0, lane)
        self.siph_write_tx_register(0x0, txcdr0 & 0xEFFF, lane)
        txcdr4 = self.siph_read_tx_register(0x4, lane)
        self.siph_write_tx_register(0x4, txcdr4 & 0xFFFE, lane)
        txcdr16 = self.siph_read_tx_register(0x10, lane)
        self.siph_write_tx_register(0x10, txcdr16 & 0xFFEF, lane)

        print("Tx-Opt DIG reset:")
        txcdr1 = self.siph_read_tx_register(0x1, lane)
        self.siph_write_tx_register(0x1, txcdr1 & 0x7FFF, lane)

        print("Rx-Ele DIG out of reset")
        txcdr19 = self.siph_read_tx_register(0x13)
        self.siph_write_tx_register(0x13, txcdr19 | 0x2000, lane)

        print("Rx-Ele power up")
        self.siph_write_tx_register(0x10, (txcdr16 & 0xFFEF) | 0x8000, lane)

        print("Tx-Opt power Up")
        self.siph_write_tx_register(0x0, (txcdr0 & 0xEFFF) | 0x8000, lane)

        "Apply MZM quadrature point algorithm. See Par 2.4.2"

    def siph_set_bypass_mode(self, lane=0):
        """
        enable the TX and RX in By-pass Mode
        """
        print('lane: %d' % (lane))
        print("TX in By-pass Mode")
        print("Set CDR By Pass Mode")
        txcdr0 = 0xEFFF & self.siph_read_tx_register(0x0, lane)
        self.siph_write_tx_register(0x0, txcdr0, lane)
        txcdr4 = self.siph_read_tx_register(0x4, lane)
        self.siph_write_tx_register(0x4, txcdr4 | 0x1, lane)
        txcdr16 = self.siph_read_tx_register(0x10, lane)
        self.siph_write_tx_register(0x10, txcdr16 | 0x10, lane)
        print("Tx-Opt DIG reset")
        txcdr1 = 0x7FFF & self.siph_read_tx_register(0x1, lane)
        self.siph_write_tx_register(0x1, txcdr1, lane)
        print("Rx-Ele DIG reset")
        txcdr19 = 0xDFFF & self.siph_read_tx_register(0x13, lane)
        self.siph_write_tx_register(0x13, txcdr19, lane)
        print("Rx-Ele power up")
        txcdr10 = self.siph_read_tx_register(0x10, lane)
        self.siph_write_tx_register(0x10, txcdr10 | 0x8000, lane)
        print("Tx-Opt power Up")
        txcdr0 = self.siph_read_tx_register(0x0, lane)
        self.siph_write_tx_register(0x0, txcdr0 | 0x8000, lane)
        print("Apply MZM quadrature point algorithm")

        print("RX in By-pass Mode")
        print("Set CDR By Pass Mode")
        rxcdr0 = 0xEFFF & self.siph_read_rx_register(0x0, lane)
        self.siph_write_rx_register(0x0, rxcdr0, lane)
        rxcdr4 = self.siph_read_rx_register(0x4, lane)
        self.siph_write_rx_register(0x4, rxcdr4 | 0x1, lane)
        rxcdr16 = self.siph_read_rx_register(0x10, lane)
        self.siph_write_rx_register(0x10, rxcdr16 | 0x10, lane)
        print("Tx-Ele DIG reset")
        rxcdr1 = 0x7FFF & self.siph_read_rx_register(0x1, lane)
        self.siph_write_rx_register(0x1, rxcdr1, lane)
        print("Rx-Opt DIG reset")
        rxcdr19 = 0xDFFF & self.siph_read_rx_register(0x13, lane)
        self.siph_write_rx_register(0x13, rxcdr19, lane)
        print("Rx-Opt power up")
        rxcdr10 = self.siph_read_tx_register(0x10, lane)
        self.siph_write_tx_register(0x10, rxcdr10 | 0x8000, lane)
        print("Tx-Ele power Up")
        rxcdr0 = self.siph_read_rx_register(0x0, lane)
        self.siph_write_rx_register(0x0, rxcdr0 | 0x8000, lane)

    def siph_set_mission_mode(self, lane=0):
        """
        enable the TX and RX in Mission Mode
        """
        print('lane: %d' % (lane))
        print('TX in Mission Mode')
        print('Set Mission Mode:')
        txcdr0 = 0xEFFF & self.siph_read_tx_register(0x0, lane)
        self.siph_write_tx_register(0x0, txcdr0, lane)
        txcdr4 = 0xFFFE & self.siph_read_tx_register(0x4, lane)
        self.siph_write_tx_register(0x4, txcdr4, lane)
        txcdr16 = 0xFFEF & self.siph_read_tx_register(0x10, lane)
        self.siph_write_tx_register(0x10, txcdr16, lane)
        print('Tx-Opt DIG reset: ')
        txcdr1 = 0x7FFF & self.siph_read_tx_register(0x1, lane)
        self.siph_write_tx_register(0x1, txcdr1, lane)
        print('Rx-Ele DIG out of reset: ')
        txcdr19 = self.siph_read_tx_register(0x13, lane)
        self.siph_write_tx_register(0x13, txcdr19 | 0x2000, lane)
        print('Rx-Ele power up:')
        txcdr16 = self.siph_read_tx_register(0x10, lane)
        self.siph_write_tx_register(0x10, txcdr16 | 0x8000, lane)
        print('Tx-Opt power Up:')
        txcdr0 = self.siph_read_tx_register(0x0, lane)
        self.siph_write_tx_register(0x0, txcdr0 | 0x8000, lane)
        print('Apply MZM quadrature point algorithm')
        print('Apply Lock CDR procedure')
        txcdr18 = self.siph_read_tx_register(0x12, lane)
        self.siph_write_tx_register(0x12, txcdr18 | 0x01, lane)
        txcdr18 = 0xFFFE & self.siph_read_tx_register(0x12, lane)
        self.siph_write_tx_register(0x12, txcdr18, lane)

        print('RX in Mission Mode')
        print('Set Mission Mode:')
        rxcdr0 = 0xEFFF & self.siph_read_rx_register(0x0, lane)
        self.siph_write_rx_register(0x0, rxcdr0, lane)
        rxcdr4 = 0xFFFE & self.siph_read_rx_register(0x4, lane)
        self.siph_write_rx_register(0x4, rxcdr4, lane)
        rxcdr16 = 0xFFEF & self.siph_read_rx_register(0x10, lane)
        self.siph_write_rx_register(0x10, rxcdr16, lane)
        print('Tx-Ele DIG reset: ')
        rxcdr1 = 0x7FFF & self.siph_read_rx_register(0x1, lane)
        self.siph_write_rx_register(0x1, rxcdr1, lane)
        print('Rx-Opt DIG out of reset: ')
        rxcdr19 = self.siph_read_rx_register(0x13, lane)
        self.siph_write_rx_register(0x13, rxcdr19 | 0x2000, lane)
        print('Rx-Opt power up:')
        rxcdr16 = self.siph_read_rx_register(0x10, lane)
        self.siph_write_rx_register(0x10, rxcdr16 | 0x8000, lane)
        print('Tx-Ele power Up:')
        rxcdr0 = self.siph_read_rx_register(0x0, lane)
        self.siph_write_rx_register(0x0, rxcdr0 | 0x8000, lane)
        print('Apply Lock CDR procedure')
        rxcdr18 = self.siph_read_rx_register(0x12, lane)
        self.siph_write_rx_register(0x12, rxcdr18 | 0x01, lane)
        rxcdr18 = 0xFFFE & self.siph_read_rx_register(0x12, lane)
        self.siph_write_rx_register(0x12, rxcdr18, lane)

    def siph_set_tx_bist_mode(self, lane=0, line='ele'):

        if line == 'ele':
            print("Set BIST Mode")
            rxcr0 = self.siph_read_rx_register(0x0)
            self.siph_write_rx_register(0x0, rxcr0 | 0x1000)

            rxcr4 = self.siph_read_rx_register(0x4)
            self.siph_write_rx_register(0x4, rxcr4 & 0xFFFE)

            rxcr16 = self.siph_read_rx_register(0x10)
            self.siph_write_rx_register(0x10, rxcr16 & 0xFFEF)

            print("Set Tx-Ele Freeze Mode")
            rxcr1 = self.siph_read_rx_register(0x01)
            self.siph_write_rx_register(0x01, rxcr1 & 0xFEFF)

            print("Set Pattern Generator and enable BIST")
            rxcr1 = 0xFFF8 & self.siph_read_rx_register(0x01)
            self.siph_write_rx_register(0x01, rxcr1 | 0x3)
            rxtc2 = 0xFFF8 & self.siph_read_rx_register(0x22)
            self.siph_write_rx_register(0x22, rxtc2 | 0x3)
            self.siph_write_rx_register(0x22, rxtc2 | 0x3 | 0x8000)

            print("Tx-Ele DIG out of reset:")
            self.siph_write_rx_register(0x01, rxcr1 | 0x3 | 0x8000)

            print("Tx-Ele power Up:")
            self.siph_write_rx_register(0x0, rxcr0 | 0x1000 | 0x8000)
        else:
            print("Set BIST Mode")
            txcr0 = 0xEFFF & self.siph_read_tx_register(0x0)
            self.siph_write_tx_register(0x0, txcr0 | 0x1000)

            txcr4 = 0xFFFE & self.siph_read_tx_register(0x4)
            self.siph_write_tx_register(0x4, txcr4)

            txcr16 = 0xFFEF & self.siph_read_tx_register(0x10)
            self.siph_write_tx_register(0x10, txcr16)

            print("Set Tx-Opt Freeze Mode")
            txcr1 = 0xFEFF & self.siph_read_tx_register(0x1)
            self.siph_write_tx_register(0x1, txcr1)

            print("Set Pattern Generator and enable BIST")
            self.siph_write_tx_register(0x1, txcr1 & 0xFFF8 | 0x03)

            txtc2 = self.siph_read_tx_register(0x22)
            self.siph_write_tx_register(0x22, txtc2 & 0xFFF8 | 0x03)
            self.siph_write_tx_register(0x22, txtc2 | 0x8000)

            print("Tx-Opt DIG out of reset")
            self.siph_write_tx_register(0x1, txcr1 & 0xFFF8 | 0x03 | 0x8000)
            print("Tx-Opt power Up")
            self.siph_write_tx_register(0x1, txcr0 | 0x8000)

    def siph_enable_rx_prbs_checker(self, lane=0, line='ele'):
        if line == 'ele':
            print("Set Error Detector PRBS7:")
            txtc2 = self.siph_read_tx_register(0x22)
            self.siph_write_tx_register(0x22, txtc2 | 0x8000)
            self.siph_write_tx_register(0x22, txtc2 | 0x8000 & 0xFF8F | 0x30)

            print("Rx-Ele DIG out of reset:")
            txcr19 = self.siph_read_tx_register(0x13)
            self.siph_write_tx_register(0x13, txcr19 | 0x2000)

            print("Rx-Ele power up:")
            txcr16 = self.siph_read_tx_register(0x10)
            self.siph_write_tx_register(0x10, txcr16 | 0x8000)
        else:
            'Here below the setting to enable the RX checker in the Rx-Opt'
            print("Set Error Detector PRBS7:")
            rxtc2 = self.siph_read_rx_register(0x22)

            self.siph_write_rx_register(0x22, rxtc2 | 0x8000)
            self.siph_write_rx_register(0x22, rxtc2 | 0x8000 & 0xFF8F | 0x30)

            print("Rx-Opt DIG out of reset: ")
            rxcr19 = self.siph_read_rx_register(0x13)
            self.siph_write_rx_register(0x13, rxcr19 | 0x2000)

            print("Rx-opt power up: ")
            rxcr16 = self.siph_read_rx_register(0x10)
            self.siph_write_rx_register(0x10, rxcr16 | 0x8000)

    def siph_sync_prbs_checker(self, lane=0, line='ele'):
        if line == 'ele':
            print('Enable the TX checker in the Rx-Ele')
            txtc2 = 0xBFFF & self.siph_read_tx_register(0x22)
            self.siph_write_tx_register(0x22, txtc2)
            self.siph_write_tx_register(0x22, txtc2 | 0x4000)
        else:
            print('Enable the RX checker in the Rx-Opt')
            rxtc2 = 0xBFFF & self.siph_read_rx_register(0x22)
            self.siph_write_rx_register(0x22, rxtc2)
            self.siph_write_rx_register(0x22, rxtc2 | 0x4000)

    def siph_bis_error_counter(self, lane=0, line='ele'):
        if line == 'ele':
            txsr4 = self.siph_read_tx_register(0x34)
            print("TXDSSR4: %x" % (txsr4))
            txtc2 = self.siph_read_tx_register(0x22)
            if txtc2 & 0x8000:
                print("Tx error reg: %x" % (txtc2))
        else:
            rxtc2 = self.siph_read_rx_register(0x22)
            if rxtc2 & 0x8000:
                print("Rx error reg: %x" % (rxtc2))

    def siph_prbs_test(self, lane=0x0, line='ele'):
        self.siph_set_tx_bist_mode(lane, line)
        print("")
        self.siph_enable_rx_prbs_checker(lane, line)
        print("")
        self.siph_sync_prbs_checker(lane, line)

    def siph_clock_slice_registers_dump(self):
        for reg in range(0x0, 0x08):
            print("0x%x" % (reg), end=' ')
            self.siph_read_register(reg)
        for reg in range(0x30, 0x36):
            print("0x%x" % (reg), end=' ')
            self.siph_read_register(reg)

    def siph_tx_slice_registers_dump(self, lane=0):
        for reg in range(0x0, 0x0A):
            print("0x%x" % (reg), end=' ')
            self.siph_read_tx_register(reg, lane)
        for reg in range(0x10, 0x19):
            print("0x%x" % (reg), end=' ')
            self.siph_read_tx_register(reg, lane)
        for reg in [0x20, 0x21, 0x22]:
            print("0x%x" % (reg), end=' ')
            self.siph_read_tx_register(reg, lane)
        for reg in range(0x30, 0x37):
            print("0x%x" % (reg), end=' ')
            self.siph_read_tx_register(reg, lane)

    def siph_rx_slice_registers_dump(self, lane=0):
        for reg in range(0x0, 0x0A):
            print("0x%x" % (reg), end=' ')
            self.siph_read_rx_register(reg, lane)
        for reg in range(0x10, 0x18):
            print("0x%x" % (reg), end=' ')
            self.siph_read_rx_register(reg, lane)
        for reg in [0x20, 0x21, 0x22]:
            print("0x%x" % (reg), end=' ')
            self.siph_read_rx_register(reg, lane)
        for reg in range(0x30, 0x37):
            print("0x%x" % (reg), end=' ')
            self.siph_read_rx_register(reg, lane)

    def siph_registers_dump(self, clock=0, tx=0, rx=0, lane=0):
        if clock:
            print("Clock Slice registers:")
            self.siph_clock_slice_registers_dump()

        if tx:
            print("TX data slice registers lane=%x" % (lane))
            self.siph_tx_slice_registers_dump(lane)

        if rx:
            print("RX data slice registers lane=%x" % (lane))
            self.siph_rx_slice_registers_dump(lane)

    def siph_adc_continuous_mode(self):
        scr4 = 0xFFCF & self.siph_read_register(0x4)
        self.siph_write_register(0x4, scr4 | 0x0)

    def siph_internal_electrical_loopback(self, lane=0):
        val = self.siph_read_tx_register(0x10, lane)
        self.siph_write_tx_register(0x10, val | 0x800, lane)
        val = self.siph_read_tx_register(0x04, lane)
        self.siph_write_tx_register(0x04, val | 0x06, lane)

        val = self.siph_read_rx_register(0x04, lane)
        self.siph_write_rx_register(0x04, val | 0x04, lane)
        val = self.siph_read_rx_register(0x10, lane)
        self.siph_write_rx_register(0x10, val | 0x800, lane)
        val = self.siph_read_rx_register(0x04, lane)
        self.siph_write_rx_register(0x04, val | 0x06, lane)

    def siph_cdr_lock_test(self, val=0, lane=0):
        cscr2 = 0xFFE0 & self.siph_read_register(0x02)
        self.siph_write_register(0x02, cscr2 | (0x1F & val))
        self.siph_set_mission_mode(lane)
        print('Value(%d) in lane(%d) TXDSSR4(0x%x)' % (val, lane, self.siph_read_tx_register(0x34, lane)))
        print('Value(%d) in lane(%d) RXDSSR4(0x%x)' % (val, lane, self.siph_read_rx_register(0x34, lane)))


if __name__ == "__main__":
    # print('port_count() = %s' % port_count())
    try:

        port = SmbPort()
        print(port.name)
        # port.enter_bootloader()
        # factory_pw = [0x7B, 0x22, 0x44, 0xA0, 0xFF]
        # factory_pw = [0x7B, 0x22, 0x44, 0x55, 0x88]
        # port.smb_write(0xA0, factory_pw, len(factory_pw))
        # page_sel = [0x7F, 0x81]
        # port.smb_write(0xA0, page_sel, len(page_sel))

        # read = port.msa_read(0xA0, 0x80, 128)
        # for len in range(0, 128, 0x10):
        #     print(''.join('{:02x}'.format(x).upper() for x in read[len:len + 0x10]))

        # port.siph_prbs_test(lane=0, line='ele')
        # port.siph_bis_error_counter(lane=0, line='ele')

        # port.siph_registers_dump(clock=1, tx=0, rx=0, lane=0)
        # port.siph_registers_dump(clock=0, tx=1, rx=1, lane=0)
        # port.siph_registers_dump(clock=0, tx=1, rx=1, lane=2)

        # print("Set clock slice register!")
        # cscr0 = port.siph_read_register(0x0)
        # port.siph_write_register(0x00, 0xf280)
        # cscr1 = port.siph_read_register(0x1)
        # port.siph_write_register(0x01, 0x003)
        # cscr2 = port.siph_read_register(0x2)
        # port.siph_write_register(0x02, 0xd748)

        # read tx registers:
        # for reg in [0x30, 0x34]:
        #     print('Register:0x%x' % (reg))
        #     port.siph_read_tx_register(reg, lane=0)
        #     port.siph_read_tx_register(reg, lane=1)
        #     port.siph_read_tx_register(reg, lane=2)
        #     port.siph_read_tx_register(reg, lane=3)
        #
        #     port.siph_read_rx_register(reg, lane=0)
        #     port.siph_read_rx_register(reg, lane=1)
        #     port.siph_read_rx_register(reg, lane=2)
        #     port.siph_read_rx_register(reg, lane=3)

        # read/write rx registers
        # cscr4 = port.siph_read_rx_register(0x2)
        # port.siph_write_rx_register(0x02, 0x0A, lane=0)

        # rx0 = port.siph_read_rx_register(0x0)
        # port.siph_write_rx_register(0x0, rx0)

        # port.siph_set_bypass_mode(lane=0)
        # port.siph_set_mission_mode(lane=0)

        # for val in range(31, -1, -1):
        #     for lane in range(4):
        #         port.siph_cdr_lock_test(val, lane)

    except HidSmbusError as e:
        print(e)

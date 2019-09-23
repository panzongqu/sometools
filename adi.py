#!/usr/bin/env python

import sys
import time
import argparse
from array import array
from intelhex import IntelHex
import efm8load

VERSION = '1.10'


class AdiPort(efm8load.Efm8SmbPort):
    """Class demonstrates how to communicate with EFM8 HID bootloader.

    This class provides functions for writing a boot frame and for reading
    the response from the EFM8 HID bootloader. Because the EFM8 HID device
    only defines one input and one output report, there is no report number.
    For Windows hosts only, read/write data exchanged with the HID driver
    is prepended with a dummy report number.
    """
    FRAME_SIZE = 0x80

    def __init__(self, fin='test.hex'):
        super(AdiPort, self).__init__(250000, 0x04)

        # public members
        self.padding = 0x0FF
        # Start Address
        self.start_addr = None

        # private members
        self._buf = IntelHex(fin).tobinarray()
        self._offset = 0

    def send_frame(self,  frame):
        """Send a boot frame and return the reply.

        Args:
            frame (bytes): A boot frame to send to the EFM8 bootloader.

        Returns:
            Reply byte as an integer. 0x3F for recognized replies and timeouts.
        """
        self.write(frame)
        print(''.join('{:02x}'.format(x) for x in frame))

        reply = self.read()
        print(reply)
        if reply and reply in [0x06, 0x07]:
            return reply
        else:
            return 0xFF

    def send_frame_bs(self):
        """
        The data of the first packet sent by the loader must
        be backspace (BS = 0x08) to start the protocol
        """
        self.write([0x08])

    def read_frame_id(self):
        """
        • 15 bytes are the product identifier
        • 4 bytes are the hardware and firmware version number
        • 3 bytes are reserved for future use
        • 2 bytes are the line feed and carriage return
        """
        id = self.smb_read(self.address, 24)
        print('Product Identifier:')
        print(''.join('{:02x}'.format(x) for x in id[0:15]))
        print('HW/FW version:')
        print(''.join('{:02x}'.format(x) for x in id[15:19]))
        print('Reserved:')
        print(''.join('{:02x}'.format(x) for x in id[19:22]))
        print('Line F&C:')
        print(''.join('{:02x}'.format(x) for x in id[22:24]))

    def send_frame_erase(self, addr=0x0, pages=None):
        """
        Send Erase Flash EE/Memory Command
        """
        bin = array('B')
        if(pages is None):
            pages = 1 + len(self._buf)//0x200

        bin.append(0x07)
        bin.append(0x0E)
        bin.append(6)
        bin.append(0x45)
        bin.append(addr >> 24 & 0x0FF)
        bin.append(addr >> 16 & 0x0FF)
        bin.append(addr >> 8 & 0x0FF)
        bin.append(addr & 0x0FF)
        bin.append(pages)
        bin.append((-sum(bin[2:])) & 0x0FF)
        self.write(bin)

        time.sleep(pages * 5/127)

        reply = self.read()
        if(reply == [0x06]):
            print('Erase the flash successfully! 0x{:04x}'.format(addr), pages)
        else:
            print('Erase the flash error')

    def send_frame_write(self, addr, buf):
        bin = array('B')

        bin.append(0x07)
        bin.append(0x0E)
        bin.append(5 + len(buf))
        bin.append(0x57)
        bin.append(addr >> 24 & 0x0FF)
        bin.append(addr >> 16 & 0x0FF)
        bin.append(addr >> 8 & 0x0FF)
        bin.append(addr & 0x0FF)
        bin.extend(buf)
        bin.append((-sum(bin[2:])) & 0x0FF)
        self.send_frame(bin)

    def send_frame_run(self):
        """
        """
        bin = array('B')
        bin.append(0x07)
        bin.append(0x0E)
        bin.append(5)
        bin.append(0x52)
        bin.append(0x00)
        bin.append(0x00)
        bin.append(0x00)
        bin.append(0x01)
        bin.append((-sum(bin[2:])) & 0x0FF)
        self.send_frame(bin)

    def send_frame_verify(self, addr, buf):
        bin = array('B')

        bin.append(0x07)
        bin.append(0x0E)
        bin.append(5 + len(buf))
        bin.append(0x56)
        bin.append(addr >> 24 & 0x0FF)
        bin.append(addr >> 16 & 0x0FF)
        bin.append(addr >> 8 & 0x0FF)
        bin.append(addr & 0x0FF)

        for i in buf:
            bin.append(0xFF & (i >> 5 | i << 3))

        bin.append((-sum(bin[2:])) & 0x0FF)
        self.send_frame(bin)

    # alias
    do_run_app = send_frame_run
    do_send_bs = send_frame_bs
    do_read_id = read_frame_id
    do_erase = send_frame_erase
    do_verify = send_frame_verify
    do_run_app = send_frame_run

    def do_program(self, verify=0):
        """
        """
        for addr in range(0x200, len(self._buf), self.FRAME_SIZE):
            self.send_frame_write(addr, self._buf[addr:addr + self.FRAME_SIZE])
            if(verify != 0):
                self.send_frame_verify(addr, self._buf[addr:addr + self.FRAME_SIZE])

    def do_program_end(self):
        """
        """
        for addr in range(0, 0x200, self.FRAME_SIZE):
            self.send_frame_write(addr, self._buf[addr:addr + self.FRAME_SIZE])
            self.send_frame_verify(addr, self._buf[addr:addr + self.FRAME_SIZE])


if __name__ == '__main__':
    # ap = argparse.ArgumentParser(description='ADuC7023 bootloader download utility.')
    # ap.add_argument('-v', '--version', action='version', version='%(prog)s ' + VERSION)
    # ap.add_argument('bootfile', type=argparse.FileType('rb'), help='hex file to download')
    # ap.add_argument('-b', '--baud', type=int, help='baudrate (SMB:100000, UART:115200)')
    # ap.add_argument('-p', '--port', help='port (default=usb | jlink)')
    # ap.add_argument('-t', '--trace', action='store_true', help='show download trace')
    # args = ap.parse_args()

    adi = AdiPort()
    adi.do_send_bs()
    adi.do_read_id()
    adi.do_erase()
    adi.do_program(0)
    adi.do_program_end()
    adi.do_run_app()

#!/usr/bin/env python
# encoding: utf-8
"""
xbeed.py

Communicates with an Xbee Series 2.5 module thorough a serial port.
Allows access to the Zigbee PAN through DBUS or XML-RPC.

Created by Rob O'Dwyer on 2009-10-21.
Copyright (c) 2009 Turk Innovations. All rights reserved.
"""

import sys
from optparse import OptionParser
from serial import Serial
from struct import pack, unpack
from StringIO import StringIO

import gobject
import dbus
import dbus.service
import dbus.mainloop.glib

XBEED_SERVICE = 'org.turkinnovations.xbeed'
XBEED_INTERFACE = 'org.turkinnovations.xbeed.XbeeInterface'
XBEED_OBJECT = '/XbeeInterfaces/%s'

DEFAULT_SERIAL_PORT = '/dev/tty.PL2303-00002006'

##########  Main serial and server classes ########## 

class XbeeDaemon(dbus.service.Object):
    """
    Main class which connects dbus API and serial communication
    name: Unique DBUS object name for this instance
    All other arguments are passed off to the underlying pySerial implementation
    """
    def __init__(self, name, port, escaping=True, baudrate=9600, timeout=0):
        if escaping:
            self.serial = FrameEscaper(port=port, baudrate=baudrate, timeout=timeout)
        else:
            self.serial = Serial(port=port, baudrate=baudrate, timeout=timeout)  
             
        self.name = name
        object_path = XBEED_OBJECT % name
        dbus.service.Object.__init__(self, dbus.SessionBus(), object_path)
        gobject.io_add_watch(self.serial.fileno(), gobject.IO_IN, self.serial_read)
        
    def serial_read(self):
        """ Called when there is data available from the serial port """
        print 'xbeed: serial data available!'
        buffer = self.serial.read(256)
        print 'xbeed: read %d chars' % len(buffer)
    
    @dbus.service.method(XBEED_INTERFACE, in_signature='tay', out_signature='')  
    def SendData(self, hw_address, data):
        print 'xbeed: SendData called, sending %d bytes to address 0x%X' % (len(data), hw_address)
    
    @dbus.service.method(XBEED_INTERFACE, in_signature='s', out_signature='as')    
    def GetInfo(self, arg):
        print 'xbeed: GetInfo called'
        return ['info1', 'info2', 'useless info', 'I\'m %s!'%self.name]

class FrameEscaper(Serial):
    """
    Escapes frame data as it's written to the serial port
    Bytes 0x7E, 0x7D, 0x11, 0x13 are escaped as [0x7D, byte^0x20]
    Note: this doesn't escape the first 0x7D
    """ 
    def write(self, data):
        Serial.write(self, ''.join(self.escape(data[1:])))
       
    def read(self, size=1):
        data = Serial.read(self, size)
         
    @staticmethod
    def escape(data):
        yield data[0]
        for byte in data[1:]:
            if byte in ['\x7E', '\x7D', '\x11', '\x13']:
                yield '\x7D'
                yield chr(ord(byte) ^ 0x20)
            else:
                yield byte
    
    @staticmethod
    def unescape(data):
        escape_flag = False
        for byte in data:
            if byte == '\x7D':
                escape_flag = True
            else:
                yield chr(ord(byte) ^ 0x20) if escape_flag else byte
                escape_flag = False
    
########## Packet Types and parsing utilities ############

class XbeeModuleFrame(object):
    """Abstract class for parsing serial API packets"""
    # Used for mapping frame data to packet types based on api_id field
    api_ids = {}
    # Used to format frame signatures based on variable-length fields
    length_mod = None
    
    @classmethod
    def parse(cls, data):
        """
        Get the length and api_id and use them to construct a specific frame structure.
        """
        length, api_id = unpack('>HB', data[1:4])
        # Raise exception containing real / expected value if checksum fails
        if not validate_checksum(data, offset=3):
            printHex(data)
            raise ChecksumFail(ord(data[-1]), generate_checksum(data))
        if not (len(data) == length + 4):
            raise InvalidPacketLength(length)
        
        # Parse and return specific packet structure
        ptype = cls.api_ids[api_id]
        if ptype.length_mod:
            signature = ptype.signature % (length - ptype.length_mod)
        else:
            signature = ptype.signature
        fields = unpack(signature, data)
        return ptype(*fields)

    @classmethod
    def api_packet(cls, packet_class):
        """ Associates a packet type with the corresponding api_id for automatic parsing """
        cls.api_ids[packet_class.api_id] = packet_class
        return packet_class
      
@XbeeModuleFrame.api_packet
class TransmitStatus(XbeeModuleFrame):
    """ When a TX Request is completed, the module sends a TX Status message. This message
        will indicate if the packet was transmitted successfully or if there was a failure."""
    signature = '>4xBHBBBx'
    api_id = 0x8B
    def __init__(self, frame_id, net_addr, retries, status, discovery):
        self.frame_id = frame_id
        self.net_addr = net_addr
        self.retries = retries
        self.status = status
        self.discovery = discovery

@XbeeModuleFrame.api_packet  
class ReceivePacket(XbeeModuleFrame):
    """ When the module receives an RF packet, it is sent out the UART using this message type. """
    signature = '>4xQHB%dsx'
    length_mod = 12
    api_id = 0x90
    def __init__(self, hw_addr, net_addr, options, rf_data):
        self.hw_addr = hw_addr
        self.net_addr = net_addr
        self.options = options
        self.rf_data = rf_data

        
class XbeeClientFrame(object):
    """Abstract class for constructing new packets to send to Xbee module"""
    def get_frame(self):
        """ Returns the binary frame representation of the packet """
        s = StringIO()
        s.write(pack('>BH', 0x7E, self.length))
        frame_data = pack(self.signature, *self.fields)
        checksum = generate_checksum(frame_data)
        s.write(frame_data)
        s.write(chr(checksum))
        return s.getvalue()
        
    def write_frame(self, fd):
        """ Writes the binary representation of the packet to a file-like object """
        fd.write(pack('>BH', 0x7E, self.length))
        frame_data = pack(self.signature, self.fields)
        checksum = generate_checksum(frame_data)
        fd.write(frame_data)
        fd.write(chr(checksum))
        
class TransmitRequest(XbeeClientFrame):
    api_id = 0x10
    signature = '>BBQHBB%ds'
    def __init__(self, hw_addr, rf_data, frame_id=0, net_addr=0xFFFE):
        self.frame_id = frame_id
        self.fields = (self.api_id, frame_id, hw_addr, net_addr, 0x00, 0x00, rf_data)
        self.signature = self.signature % len(rf_data)
        self.length = len(rf_data) + 14
   
   
   
##########  Checksum generation and validation ##########      

def generate_checksum(frame, offset=0):
    """ Generates the checksum byte for this frame. The algorithm consists of
    adding all bytes in the frame data and subtracting the result from 0xFF.
    NOTE: this assumes the checksum is initially set to zero or not included """
    return 0xFF - (reduce(lambda x, y: x + ord(y), frame[offset:], 0x00) & 0xFF)
    
def validate_checksum(frame, offset=0):
    """ Validates the checksum by adding all bytes and comparing to 0xFF """
    return (reduce(lambda x, y: x + ord(y), frame[offset:], 0x00) & 0xFF) == 0xFF


##########  Exceptions / Errors ##########  

class ChecksumFail(Exception):
    def __str__(self):
        return '0x%X != 0x%X' % self.args if len(self.args) is 2 else None
        
class InvalidPacketLength(Exception): pass

class UnknownFrameType(Exception):
    pass

########## Utility Functions ###########

def getXbeeByName(name):
    return (XBEED_SERVICE, XBEED_OBJECT % name)
  
def printHex(data):
    for byte in data:
        print '0x%X ' % ord(byte),
    print  
     

   
def main1():
     dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)

     name = dbus.service.BusName(XBEED_SERVICE, dbus.SessionBus())
     daemon = XbeeDaemon('Xbee0', DEFAULT_SERIAL_PORT)

     mainloop = gobject.MainLoop()
     print "Running Xbeed interface."
     mainloop.run()       

def main(argv=None):
    usage = "usage: %prog [options] <serial port> <dbus label>"
    parser = OptionParser(usage)
    parser.add_option("-q", "--quiet",
                      action="store_false", dest="verbose", default=True,
                      help="don't print status messages to stdout")
    parser.add_option("-f", "--foreground",
                      action="store_false", dest="daemon", default=True,
                      help="run in foreground instead of forking a daemon process")
    (options, args) = parser.parse_args()
    if len(args) != 1:
            parser.error("incorrect number of arguments")
    

if __name__ == "__main__":
    sys.exit(main())

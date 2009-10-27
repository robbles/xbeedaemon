#!/usr/bin/env python
# encoding: utf-8
"""
xbeed.py

Communicates with an XBee Series 2.5 module thorough a serial port.
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
XBEED_INTERFACE = 'org.turkinnovations.xbeed.XBeeInterface'
XBEED_DAEMON_OBJECT = '/XBeeInterfaces/%s'
XBEED_MODULE_OBJECT = '/XBeeModules/%X'

######################## Main serial and server classes ########################

class XBeeDaemon(dbus.service.Object):
    """
    Main class which connects dbus API and serial communication
    name: Unique DBUS object name for this instance
    All other arguments are passed off to the underlying pySerial implementation
    """
    def __init__(self, name, port, escaping=True, baudrate=9600):
        if escaping:
            self.serial = FrameEscaper(port=port, baudrate=baudrate, timeout=0)
        else:
            self.serial = Serial(port=port, baudrate=baudrate, timeout=0)  
             
        self.object_path = XBEED_DAEMON_OBJECT % name
        self.partial = PartialFrame()
        
        dbus.service.Object.__init__(self, dbus.SessionBus(), self.object_path)
        gobject.io_add_watch(self.serial.fileno(), gobject.IO_IN, self.serial_read)
        
    def serial_read(self, fd, condition, *args):
        """ Called when there is data available from the serial port """
        buffer = self.serial.read(256)
        
        try:
            if(self.partial.add(buffer)):
                packet = XBeeModuleFrame.parse(*self.partial.get_data())
                self.handle_packet(packet)
        except ChecksumFail, e:
            print e      
        return True # Keep calling this function when data is available
    
    def handle_packet(self, packet):
        if isinstance(packet, TransmitStatus):
            print 'Transmit status for packet %d received: %s' % (packet.frame_id, packet.status)
        elif isinstance(packet, ReceivePacket):
            XBeeModule(packet.hw_addr).RecievedData(packet.rf_data)
    
    @dbus.service.method(XBEED_INTERFACE, in_signature='tayy', out_signature='')  
    def SendData(self, hw_addr, rf_data, frame_id):
        """ Sends an RF data packet to the specified XBee module """
        print 'xbeed: SendData called, sending %d bytes to address 0x%X' % (len(rf_data), hw_addr)
        packet = TransmitRequest(hw_addr=hw_addr, rf_data=str(rf_data), frame_id=frame_id)
        packet.write_frame(self.serial)
    
    @dbus.service.method(XBEED_INTERFACE, in_signature='s', out_signature='s')    
    def GetInfo(self, arg):
        """ Returns some marginally useful info about the current xbeed instance """
        print 'xbeed: GetInfo called'
        return self.object_path
        
class FrameEscaper(Serial):
    """
    Escapes frame data as it's written to the serial port
    Bytes 0x7E, 0x7D, 0x11, 0x13 are escaped as [0x7D, byte^0x20]
    Note: this doesn't escape the first 0x7D
    """ 
    def write(self, data):
        Serial.write(self, ''.join(escape(data)))
       
    def read(self, size=1):
        data = Serial.read(self, size)
        escaped = ''.join(unescape(data))
        return escaped


###################### Packet Types and parsing utilities ######################

class PartialFrame(object):
    """ Stores up serial data until a full frame is received """
    def __init__(self):
        self.buffer = ''
        self.frame_len = 0
        self.last = ()
        
    def add(self, data):
        """ Adds new data to the frame, returning True if frame is complete """
        self.buffer = ''.join([self.buffer, data])
        if len(self.buffer) >= 6:
            if not self.frame_len:
                self.frame_len, self.api_id = unpack('>HB', self.buffer[1:4])
            if len(self.buffer) >= (self.frame_len + 4):
                self.last = (self.buffer[:self.frame_len+4], self.api_id, self.frame_len)
                self.buffer = self.buffer[self.frame_len+4:]
                self.frame_len = 0
                return True
        return False
        
    def get_data(self):
        return self.last


class XBeeModuleFrame(object):
    """Abstract class for parsing serial API packets"""
    # Used for mapping frame data to packet types based on api_id field
    api_ids = {}
    # Used to format frame signatures based on variable-length fields
    length_mod = None
    
    @classmethod
    def parse(cls, data, api_id, length):
        print 'XBeeModuleFrame: parsing packet with length %d, api_id 0x%X' % (length, api_id)
        # Raise exception containing real / expected value if checksum fails
        if not validate_checksum(data, offset=3):
            raise ChecksumFail(ord(data[-1]), generate_checksum(data))
        
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
      
@XBeeModuleFrame.api_packet
class TransmitStatus(XBeeModuleFrame):
    """ When a TX Request is completed, the module sends a TX Status message. This message
        will indicate if the packet was transmitted successfully or if there was a failure."""
    signature = '>4xBHBBBx'
    api_id = 0x8B
    statuses = {0x00:'Success', 0x02:'CCA Failure', 0x15:'Invalid Destination', 0x21:'ACK Failure',
                0x22:'Not Joined', 0x23:'Self-Addressed', 0x24:'Address Not Found', 0x25:'Route Not Found'}
    def __init__(self, frame_id, net_addr, retries, status, discovery):
        self.frame_id = frame_id
        self.net_addr = net_addr
        self.retries = retries
        self.status = (status, self.statuses.get(status, 'Unknown Status'))
        self.discovery = discovery

@XBeeModuleFrame.api_packet  
class ReceivePacket(XBeeModuleFrame):
    """ When the module receives an RF packet, it is sent out the UART using this message type. """
    signature = '>4xQHB%dsx'
    length_mod = 12
    api_id = 0x90
    def __init__(self, hw_addr, net_addr, options, rf_data):
        self.hw_addr = hw_addr
        self.net_addr = net_addr
        self.options = options
        self.rf_data = rf_data

        
class XBeeClientFrame(object):
    """Abstract class for constructing new packets to send to XBee module"""
    def get_frame(self):
        """ Returns the binary frame representation of the packet """
        s = StringIO()
        self.write_frame(s)
        return s.getvalue()
        
    def write_frame(self, fd):
        """ Writes the binary representation of the packet to a file-like object """
        fd.write(pack('>BH', 0x7E, self.length))
        frame_data = pack(self.signature, *self.fields)
        checksum = generate_checksum(frame_data)
        fd.write(frame_data)
        fd.write(chr(checksum))
        
class TransmitRequest(XBeeClientFrame):
    api_id = 0x10
    signature = '>BBQHBB%ds'
    def __init__(self, hw_addr, rf_data, frame_id=0, net_addr=0xFFFE):
        self.frame_id = frame_id
        self.fields = (self.api_id, frame_id, hw_addr, net_addr, 0x00, 0x00, rf_data)
        self.signature = self.signature % len(rf_data)
        self.length = len(rf_data) + 14
   
   
############################## XBee Status Object ##############################

class XBeeModule(dbus.service.Object):
    """ Represents a remote XBee module, and signals when packets are received
        from that module."""
    modules = {}
    def __new__(cls, hw_addr):
        if hw_addr not in cls.modules:
            cls.modules[hw_addr] = dbus.service.Object.__new__(cls, hw_addr)
        return cls.modules[hw_addr]
        
    def __init__(self, hw_addr):
        dbus.service.Object.__init__(self, dbus.SessionBus(), XBEED_MODULE_OBJECT % (hw_addr))
    
    @dbus.service.signal(dbus_interface=XBEED_INTERFACE, signature='ay') 
    def RecievedData(self, rf_data):
        """ Called when data is received from the module """
        print 'Received a packet of length %d' % len(rf_data)
       
###################### Checksum generation and validation ######################
     
def generate_checksum(frame, offset=0):
    """ Generates the checksum byte for this frame. The algorithm consists of
    adding all bytes in the frame data and subtracting the result from 0xFF.
    NOTE: this assumes the checksum is initially set to zero or not included """
    return 0xFF - (reduce(lambda x, y: x + ord(y), frame[offset:], 0x00) & 0xFF)
    
def validate_checksum(frame, offset=0):
    """ Validates the checksum by adding all bytes and comparing to 0xFF """
    return (reduce(lambda x, y: x + ord(y), frame[offset:], 0x00) & 0xFF) == 0xFF


############################# Exceptions / Errors ##############################

class ChecksumFail(Exception):
    def __str__(self):
        return '0x%X != 0x%X' % self.args if len(self.args) is 2 else None
        
class InvalidPacketLength(Exception): pass

class UnknownFrameType(Exception):
    pass
    
class SendFailure(dbus.DBusException):
    _dbus_error_name = 'org.turkinnovations.xbeed.SendFailure'


############################## Utility Functions ###############################

def escape(data):
    yield data[0]
    for byte in data[1:]:
        if byte in ['\x7E', '\x7D', '\x11', '\x13']:
            yield '\x7D'
            yield chr(ord(byte) ^ 0x20)
        else:
            yield byte

def unescape(data):
    escape_flag = False
    for byte in data:
        if byte == '\x7D':
            escape_flag = True
        else:
            yield chr(ord(byte) ^ 0x20) if escape_flag else byte
            escape_flag = False


def getDaemonByName(name):
    return (XBEED_SERVICE, XBEED_DAEMON_OBJECT % name)
  
def getModuleByName(hw_addr):
    return (XBEED_SERVICE, XBEED_MODULE_OBJECT % hw_addr)
    
def printHex(data):
    print '#'
    for byte in data:
        print '0x%X ' % ord(byte),
    print '#' 
     

def main(argv=None):
    usage = "usage: %prog [options] <dbus label> <serial port>"
    parser = OptionParser(usage)
    parser.add_option("-q", "--quiet",
                      action="store_false", dest="verbose", default=True,
                      help="don't print status messages to stdout")
    parser.add_option("-f", "--foreground",
                      action="store_false", dest="daemon", default=True,
                      help="run in foreground instead of forking a daemon process")
    parser.add_option("-b", "--baudrate", dest="baudrate", type="int", default=9600,
                      help="set serial baudrate")
    parser.add_option("-n", "--no-escaping",
                      action="store_false", dest="escaping", default="True",
                      help="disable escaping of serial frame data")

    (options, args) = parser.parse_args()
    if len(args) != 2:
            parser.error("incorrect number of arguments")
    
    dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)

    name = dbus.service.BusName(XBEED_SERVICE, dbus.SessionBus())
    daemon = XBeeDaemon(name=args[0], port=args[1], baudrate=options.baudrate, escaping=options.escaping)

    mainloop = gobject.MainLoop()
    print "Running xbeed interface..."
    mainloop.run()     

if __name__ == "__main__":
    sys.exit(main())

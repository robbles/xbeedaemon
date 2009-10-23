#!/usr/bin/env python
# encoding: utf-8
"""
xbeed.py

Communicates with an Xbee Series 2.5 module thorough a serial port.
Allows access to the Zigbee PAN through a UNIX socket / XML-RPC API.

Created by Rob O'Dwyer on 2009-10-21.
Copyright (c) 2009 Turk Innovations. All rights reserved.
"""
from pdb import set_trace

import sys
import os
import unittest
import serial
from SocketServer import UnixDatagramServer
from struct import pack, unpack
from StringIO import StringIO

""" Main serial and server classes """

class XbeeDaemon(UnixDatagramServer):
    """
    Main class which connects socket API and serial communication
    """
    def __init__(self, port, *kwargs):
        self.framewrapper = FrameWrapper(port, *kwargs)
        raise NotImplementedError()

class FrameWrapper(object):
    """
    Encapsulates the Xbee serial framing protocol as a interface that can be passed XbeePackets
    """ 
    
    def __init__(self, escaping=True, port='/dev/ttyUSB0', baudrate=115200, bytesize=8, parity='N', stopbits=1):
        self.port = port
        self.tty = serial.Serial(port=port, baudrate=baudrate, bytesize=bytesize, parity=parity, stopbits=stopbits)
        self.escaping = escaping
        raise NotImplementedError()
    
""" Packet Types and parsing utilities """

class XbeeModuleFrame(object):
    """Abstract class for parsing serial API packets"""
    _api_ids = {}
        
    @classmethod
    def parse(cls, data):
        """
        Get the length and api_id and use them to construct a specific frame structure.
        """
        length, api_id = unpack('>HB', data[1:4])
        if not validate_checksum(data, offset=3):
            raise ChecksumFailed(checksum)
        if not (len(data) == length + 4):
            raise InvalidPacketLength(length)
        
        # Parse and return specific packet structure
        ptype = cls._api_ids[api_id]
        fields = unpack(ptype._signature, data[4:-1])
        return ptype(*fields)

    @classmethod
    def api_packet(cls, packet_class):
        """
        Associates a packet type with the corresponding api_id for automatic parsing
        """
        cls._api_ids[packet_class._api_id] = packet_class
        return packet_class
        
    
      
@XbeeModuleFrame.api_packet  
class TransmitStatus(XbeeModuleFrame):
    """ Indicates the status of a previous transmission attempt. The frame_id field indicates which packet it refers to."""
    _signature = '>BHBBB'
    _api_id = 0x8B
    def __init__(self, frame_id, net_addr, retries, status, discovery):
        self.frame_id = frame_id
        self.net_addr = net_addr
        self.retries = retries
        self.status = status
        self.discovery = discovery
              
        
  
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
    _api_id = 0x10
    _signature = '>BBQHBB%ds'
    def __init__(self, hw_addr, rf_data, frame_id=0, net_addr=0xFFFE):
        self.frame_id = frame_id
        self.fields = (self._api_id, frame_id, hw_addr, net_addr, 0x00, 0x00, rf_data)
        self.signature = self._signature % len(rf_data)
        self.length = len(rf_data) + 14
   
   
   
""" Checksum generation and validation """     

def generate_checksum(frame, offset=0):
    """ Generates the checksum byte for this frame. The algorithm consists of
    adding all bytes in the frame data and subtracting the result from 0xFF.
    NOTE: this assumes the checksum is initially set to zero or not included """
    return 0xFF - (reduce(lambda x, y: x + ord(y), frame[offset:], 0x00) & 0xFF)
    
def validate_checksum(frame, offset=0):
    """ Validates the checksum by adding all bytes and comparing to 0xFF """
    return (reduce(lambda x, y: x + ord(y), frame[offset:], 0x00) & 0xFF) == 0xFF



""" Unit testing"""

class xbeedTests(unittest.TestCase):
    def setUp(self):
        self.TransmitRequest_frame = '\x7E\x00\x16\x10\x01\x00\x13\xA2\x00\x40\x0A\x01\x27\xFF\xFE\x00\x00\x54\x78\x44\x61\x74\x61\x30\x41\x13'
        self.ZigbeeTransmitStatus_frame = '\x7E\x00\x07\x8B\x01\xFF\xFE\x01\x24\x00\x51'
        
    def test_api_ids(self):
        """ Test to make sure all api_ids are associated with the right packet type """
        self.failUnless(XbeeModuleFrame._api_ids[0x8B] == TransmitStatus)

    def test_generate_checksum(self):
        csum = generate_checksum(self.TransmitRequest_frame[:-1], offset=3)
        self.failUnless(csum == ord(self.TransmitRequest_frame[-1]))
        
        csum = generate_checksum(self.ZigbeeTransmitStatus_frame[:-1], offset=3)
        self.failUnless(csum == ord(self.ZigbeeTransmitStatus_frame[-1]))
        
    def test_validate_checksum(self):
        self.failUnless(validate_checksum(self.TransmitRequest_frame, offset=3))
        self.failUnless(validate_checksum(self.ZigbeeTransmitStatus_frame, offset=3))

    def test_TransmitRequest1(self):
        """ Try to build a TransmitRequest frame """
        packet = TransmitRequest(frame_id=0x01, hw_addr=0x0013A200400A0127, net_addr=0xFFFE, rf_data='TxData0A')
        frame = packet.get_frame()        
        self.failUnless(frame == self.TransmitRequest_frame)

    def test_TransmitStatus1(self):
        packet = XbeeModuleFrame.parse(self.ZigbeeTransmitStatus_frame)
        self.failUnless(isinstance(packet, TransmitStatus))
        
        
        
        
        
        
        

if __name__ == '__main__':
    unittest.main()
    
    
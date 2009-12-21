import unittest
from xbeed import *

TransmitRequest_frame = '\x00\x16\x10\x01\x00\x13\xA2\x00\x40\x0A\x01\x27\xFF\xFE\x00\x00\x54\x78\x44\x61\x74\x61\x30\x41\x13'
TransmitRequest_frame_escaped = '\x00\x16\x10\x01\x00\x7D\x33\xA2\x00\x40\x0A\x01\x27\xFF\xFE\x00\x00\x54\x78\x44\x61\x74\x61\x30\x41\x7D\x33'
TransmitStatus_frame = '\x00\x07\x8B\x01\xFF\xFE\x01\x24\x00\x51'
ReceivePacket_frame = '\x00\x10\x90\x11\x11\x11\x11\x11\x11\x11\x11\x22\x22\x01\x00\x00\x00\x00\xA2'

XBEE0 = 0x0013A2004052989D
XBEE1 = 0x0013A200400A0127
XBEE2 = 0x0013A2004052DA9A


class xbeedTests(unittest.TestCase):
    def setUp(self):        
        pass

    def test_generate_checksum(self):
        print 'checksum test'
        csum = generate_checksum(TransmitRequest_frame[:-1], offset=2)
        self.failUnless(csum == ord(TransmitRequest_frame[-1]))
        
        csum = generate_checksum(TransmitStatus_frame[:-1], offset=2)
        self.failUnless(csum == ord(TransmitStatus_frame[-1]))
    
    def test_validate_checksum(self):
        self.failUnless(validate_checksum(TransmitRequest_frame, offset=2))
        self.failUnless(validate_checksum(TransmitStatus_frame, offset=2))

    def test_TransmitRequest1(self):
        """ Try to build a TransmitRequest frame """
        packet = TransmitRequest(frame_id=0x01, hw_addr=0x0013A200400A0127, net_addr=0xFFFE, rf_data='TxData0A')
        frame = packet.get_frame()        
        self.failUnless(frame[1:] == TransmitRequest_frame)
        
    def test_TransmitStatus1(self):
        packet = XBeeModuleFrame.parse(TransmitStatus_frame, TransmitStatus.api_id, len(TransmitStatus_frame) - 4)
        self.failUnless(isinstance(packet, TransmitStatus))
       
    def test_ReceivePacket_frame(self):
        packet = XBeeModuleFrame.parse(ReceivePacket_frame, ReceivePacket.api_id, len(ReceivePacket_frame) - 3)
    
    def test_escape(self):
        escaped = ''.join(escape(TransmitRequest_frame))
        self.failUnless(escaped == TransmitRequest_frame_escaped)
    
    def test_unescape(self):
        unescaped = ''.join(unescape(TransmitRequest_frame_escaped))
        self.failUnless(unescaped == TransmitRequest_frame)

    def test_SendData(self):
        print 'testing SendData'
        bus = dbus.SystemBus()
        xbee = get_daemon('xbee0', bus)
        address = dbus.UInt64(XBEE0)
        response = xbee.SendData('hello', address, 1)
        self.failUnless(response == None)

        print 'done testing SendData'
        
if __name__ == '__main__':
    unittest.main()

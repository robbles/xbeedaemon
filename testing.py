import unittest
from xbeed import *

def enable(run_test=True):
    if run_test:
        return lambda test: test
    else:
        return lambda test: None

TransmitRequest_frame = '\x7E\x00\x16\x10\x01\x00\x13\xA2\x00\x40\x0A\x01\x27\xFF\xFE\x00\x00\x54\x78\x44\x61\x74\x61\x30\x41\x13'
TransmitRequest_frame_escaped = '\x7E\x00\x16\x10\x01\x00\x7D\x33\xA2\x00\x40\x0A\x01\x27\xFF\xFE\x00\x00\x54\x78\x44\x61\x74\x61\x30\x41\x7D\x33'
ZigbeeTransmitStatus_frame = '\x7E\x00\x07\x8B\x01\xFF\xFE\x01\x24\x00\x51'
ReceivePacket_frame = '\x7E\x00\x10\x90\x11\x11\x11\x11\x11\x11\x11\x11\x22\x22\x01\x00\x00\x00\x00\xA2'

XBEE0 = 0x0013A2004052989D
XBEE1 = 0x0013A200400A0127
XBEE2 = 0x0013A2004052DA9A

class xbeedTests(unittest.TestCase):
    def setUp(self):        
        pass
    
    @enable()  
    def testapi_ids(self):
        """ Test to make sure all api_ids are associated with the right packet type """
        self.failUnless(XbeeModuleFrame.api_ids[0x8B] == TransmitStatus)

    @enable()
    def test_generate_checksum(self):
        csum = generate_checksum(TransmitRequest_frame[:-1], offset=3)
        self.failUnless(csum == ord(TransmitRequest_frame[-1]))
        
        csum = generate_checksum(ZigbeeTransmitStatus_frame[:-1], offset=3)
        self.failUnless(csum == ord(ZigbeeTransmitStatus_frame[-1]))
    
    @enable()    
    def test_validate_checksum(self):
        self.failUnless(validate_checksum(TransmitRequest_frame, offset=3))
        self.failUnless(validate_checksum(ZigbeeTransmitStatus_frame, offset=3))

    @enable()
    def test_TransmitRequest1(self):
        """ Try to build a TransmitRequest frame """
        packet = TransmitRequest(frame_id=0x01, hw_addr=0x0013A200400A0127, net_addr=0xFFFE, rf_data='TxData0A')
        frame = packet.get_frame()        
        self.failUnless(frame == TransmitRequest_frame)
        
    @enable()
    def test_TransmitStatus1(self):
        packet = XbeeModuleFrame.parse(ZigbeeTransmitStatus_frame)
        self.failUnless(isinstance(packet, TransmitStatus))
       
    @enable()
    def test_ReceivePacket_frame(self):
        packet = XbeeModuleFrame.parse(ReceivePacket_frame)
    
    @enable()   
    def test_escape(self):
        escaped = ''.join(FrameEscaper.escape(TransmitRequest_frame))
        self.failUnless(escaped == TransmitRequest_frame_escaped)
    
    @enable()    
    def test_unescape(self):
        unescaped = ''.join(FrameEscaper.unescape(TransmitRequest_frame_escaped))
        self.failUnless(unescaped == TransmitRequest_frame)

    @enable(False)
    def test_GetInfo(self):
        try:
            bus = dbus.SessionBus()
            xbee = bus.get_object(*getXbeeByName('Xbee0'))
            response = xbee.GetInfo('give me some info')
            print 'received \'%s\' from calling Xbee0.GetInfo()' % response
        except dbus.DBusException, e:
            self.fail(e)

    @enable()
    def test_SendData(self):
        try:
            bus = dbus.SessionBus()
            xbee = bus.get_object(*getXbeeByName('Xbee0'))
            address = dbus.UInt64(XBEE0)
            response = xbee.SendData(address, 'hello', 1)
            self.failUnless(response == None)
        except dbus.DBusException, e:
            self.fail(e)
            
        
if __name__ == '__main__':
    unittest.main()

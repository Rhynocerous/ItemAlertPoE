#!/usr/bin/env python
# -*- coding: ISO-8859-1 -*-

'''
sku wrote this program. As long as you retain this notice you
can do whatever you want with this stuff. If we meet some day, and you think
this stuff is worth it, you can buy me a beer in return.
'''


from os import system as OMGDONT
from ItemList import getItem, getItemName
from NotifyItems import shouldNotify
from ByteBuffer import ByteBuffer
import ctypes
import sys
import threading
import winsound
import atexit
import datetime
import traceback

try:
    from pydbg import *
    from pydbg.defines import *
except:
    print 'You seem to be missing pydbg or pydasm.'
    print 'Precompiled binaries can be downloaded from here: http://www.lfd.uci.edu/~gohlke/pythonlibs/#pydbg'
    sys.exit(1)

ALERT_VERSION = '20130202c'
POE_VERSION = '0.10.0e'

class PlaySoundWorker(threading.Thread):
    def run(self):
        winsound.PlaySound(r'C:\Windows\Media\Sonata\Windows Notify.wav', winsound.SND_FILENAME)

class ItemAlert(object):

    BP0 = 0x005B3E79
    BP1 = 0x005B3EBD
    BP2 = 0x005B3EBF

    def __init__(self):
        atexit.register(self.atExit)
        self.logFile = open('log.txt', 'a', 0)
        print >>self.logFile, 40 * '='
        print >>self.logFile, str.format('Started ItemAlertPoE version {0} at {1!s}.', ALERT_VERSION, datetime.datetime.now())
        print >>self.logFile, str.format('Python version: {0!s}', sys.version_info)
        self.dbg = pydbg()
        self.dbg.attach(self.getProcessId())
        self.baseAddress = self.getBaseAddress()
        adjustment = self.baseAddress - 0x00400000
        ItemAlert.BP0 += adjustment
        ItemAlert.BP1 += adjustment
        ItemAlert.BP2 += adjustment
        self.lastPacketBufferAddress = 0
        self.lastPacketSize = 0

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        self.logFile.close()

    def grabPacketSize(self, dbg):
        self.lastPacketSize = dbg.get_register('eax')
        return DBG_CONTINUE

    def beforeDemanglingPacket(self, dbg):
        self.lastPacketBufferAddress = dbg.get_register('eax')
        return DBG_CONTINUE

    def parseWorldItemPacket(self, packetData):
        try:
            buffer = ByteBuffer(packetData)
            buffer.setEndian(ByteBuffer.BIG_ENDIAN)

            id = buffer.nextByte()
            objectType = buffer.nextDword()
            unk1 = buffer.nextDword()
            unk2 = buffer.nextByte()
            if unk2 != 0: 
                print >>self.logFile, 'The following packet has an odd unk2 field:'
                print >>self.logFile, self.dbg.hex_dump(map(lambda x: chr(x), packetData))
                return

            x = buffer.nextDword()
            y = buffer.nextDword()
            rot = buffer.nextDword()

            unk3 = buffer.nextDword(ByteBuffer.LITTLE_ENDIAN)
            unk4 = buffer.nextDword()

            if unk3 >> 2 != 0:
                print >>self.logFile, 'The following packet has an odd unk3 field:'
                print >>self.logFile, self.dbg.hex_dump(map(lambda x: chr(x), packetData))
                buffer.nextDword()
                buffer.nextDword()

            unk5 = buffer.nextByte()
            if unk5 != 0:
                print >>self.logFile, 'The following packet has an odd unk5 field:'
                print >>self.logFile, self.dbg.hex_dump(map(lambda x: chr(x), packetData))
                return

            unk5 = buffer.nextDword()
            if unk5 != 0: buffer.nextDword()

            unk6 = buffer.nextByte()
            itemId = buffer.nextDword()
            itemName = getItemName(itemId)
            print >>self.logFile, str.format('Detected item drop: {0} (id=0x{1:08x})', itemName, itemId)
            if shouldNotify(itemName):
                print str.format('Detected item drop: {0}', itemName)
                worker = PlaySoundWorker()
                worker.start()
        except: pass

    def afterDemanglingPacket(self, dbg):
        if self.lastPacketBufferAddress != 0 and self.lastPacketSize > 1:
            packetData = dbg.read_process_memory(self.lastPacketBufferAddress, self.lastPacketSize)
            packetData = map(lambda x: ord(x), packetData)
            for i in range(self.lastPacketSize):
                if packetData[i:i+5] == [0xf0, 0x54, 0x92, 0x8a, 0x3a]:
                    self.parseWorldItemPacket(packetData[i:])
        return DBG_CONTINUE

    def getProcessId(self):
        clients = [x[0] for x in self.dbg.enumerate_processes() if x[1].lower() == 'client.exe']
        print >>self.logFile, str.format('"Client.exe" processes found: {0!s}', clients)
        pid = None
        if not clients or len(clients) == 0: print 'No "client.exe" process found.'
        elif len(clients) > 1: print 'Found more than one "client.exe" process.'
        else: pid = clients[0]
        return pid

    def getBaseAddress(self):
        base = [x[1] for x in self.dbg.enumerate_modules() if x[0].lower() == 'client.exe'][0]
        print >>self.logFile, str.format('Base address: 0x{0:08x}', base)
        return base

    def run(self):
        print >>self.logFile, str.format('bp0: 0x{0:08x}: {1}', ItemAlert.BP0, self.dbg.disasm(ItemAlert.BP0))
        print >>self.logFile, str.format('bp1: 0x{0:08x}: {1}', ItemAlert.BP1, self.dbg.disasm(ItemAlert.BP1))
        print >>self.logFile, str.format('bp2: 0x{0:08x}: {1}', ItemAlert.BP2, self.dbg.disasm(ItemAlert.BP2))
        try:
            self.dbg.bp_set(ItemAlert.BP0, handler=self.grabPacketSize)
            self.dbg.bp_set(ItemAlert.BP1, handler=self.beforeDemanglingPacket)
            self.dbg.bp_set(ItemAlert.BP2, handler=self.afterDemanglingPacket)
        except Exception as inst:
            print >>self.logFile, type(inst)
            print >>self.logFile, inst.args
            print >>self.logFile, inst
            traceback.print_exc(file=self.logFile)
        print >>self.logFile, 'Starting main loop.'
        try: self.dbg.debug_event_loop()
        except: pass

    def atExit(self):
        try: self.dbg.detach()
        except: pass

def checkVersion():
    if ctypes.sizeof(ctypes.c_voidp) != 4:
        print 'This program only works with a 32-bit Python installation!'
        print 'The preferred (tested) version is Python 2.7, 32-bit.'
        print 'You can download it from here: http://www.python.org/ftp/python/2.7.3/python-2.7.3.msi'
        sys.exit(1)

def main():
    OMGDONT('title Path of Exile ItemAlert by sku')
    checkVersion()
    print str.format('Starting ItemAlert {0} for Path of Exile {1} by sku', ALERT_VERSION, POE_VERSION)
    with ItemAlert() as alerter: alerter.run()

if __name__ == '__main__':
    main()
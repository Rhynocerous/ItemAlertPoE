#!/usr/bin/env python
# -*- coding: ISO-8859-1 -*-

'''
sku wrote this program. As long as you retain this notice you
can do whatever you want with this stuff. If we meet some day, and you think
this stuff is worth it, you can buy me a beer in return.
'''


def makeDword(bytes, endian):
    if endian == ByteBuffer.LITTLE_ENDIAN:
        return bytes[0] | bytes[1] << 8 | bytes[2] << 16 | bytes[3] << 24
    else:
        return bytes[3] | bytes[2] << 8 | bytes[1] << 16 | bytes[0] << 24

class ByteBuffer(object):

    LITTLE_ENDIAN = 1
    BIG_ENDIAN = 2

    def __init__(self, bytes):
        self.bytes = bytes
        self.position = 0
        self.length = len(bytes)
        self.endian = ByteBuffer.LITTLE_ENDIAN

    def setEndian(self, endian):
        self.endian = endian

    def getRemainingBytes(self):
        return self.length - self.position

    def nextByte(self):
        assert self.getRemainingBytes() >= 1
        byte = self.bytes[self.position]
        self.position += 1
        return byte

    def nextDword(self, endian=None):
        assert self.getRemainingBytes() >= 4
        dword = self.bytes[self.position:self.position+4]
        self.position += 4
        return makeDword(dword, self.endian if not endian else endian)
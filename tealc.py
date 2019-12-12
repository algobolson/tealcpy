#!/usr/bin/env python3

import base64
import hashlib
import io
import json
import logging
import os
import re
import sys

import algosdk

logger = logging.getLogger(__name__)

def load_langspec():
    with open(os.path.join(os.path.dirname(__file__), 'langspec.json'), 'rt') as fin:
        return json.load(fin)

def ops_by_name(spec):
    return {x['Name']:x for x in spec['Ops']}

def to_varuint(x):
    out = []
    while True:
        tb = x & 0x7f
        x = x >> 7
        if x != 0:
            tb = tb | 0x80
        out.append(tb)
        if x == 0:
            break
    return bytes(out)

b32re = re.compile(r'b32\((.*?)\)')
base32re = re.compile(r'base32\((.*?)\)')
b64re = re.compile(r'b64\((.*?)\)')
base64re = re.compile(r'base64\((.*?)\)')

def parseByteConstant(args):
    if args[0] in ('b32', 'base32'):
        return base64.b32decode(args[1]), args[2:]
    if args[0] in ('b64', 'base64'):
        return base64.b64decode(args[1]), args[2:]
    if args[0].startswith('0x'):
        return base64.b16decode(args[0][2:].upper()), args[1:]
    m = b32re.match(args[0]) or base32re.match(args[0])
    if m:
        return base64.b32decode(m.group(1)), args[1:]
    m = b64re.match(args[0]) or base64re.match(args[0])
    if m:
        return base64.b64decode(m.group(1)), args[1:]
    raise Exception("could not parse byte constant args {!r}".format(args))

_intc_ops = {
    0: b'\x22',
    1: b'\x23',
    2: b'\x24',
    3: b'\x25',
}
_bytec_ops = {
    0: b'\x28',
    1: b'\x29',
    2: b'\x2a',
    3: b'\x2b',
}
_arg_ops = {
    0: b'\x2d',
    1: b'\x2e',
    2: b'\x2f',
    3: b'\x30',
}
class Assembler:
    def __init__(self, sourceName='', version=1):
        self.out = io.BytesIO()
        self.intc = []
        self.intcWritten = False
        self.bytec = []
        self.bytecWritten = False
        self.sourceName = sourceName
        self.sourceLine = 0
        self.labels = {}
        self.labelReferences = []
        self.spec = load_langspec()
        self.opByName = ops_by_name(self.spec)
        self.version = 1

    def setLabel(self, label):
        if label in self.labels:
            raise Exception("duplicate label {!r}".format(label))
        self.labels[label] = self.out.tell()

    def referenceLabel(self, sourceLine, pc, label):
        self.labelReferences.append( (sourceLine, pc, label) )

    def write_intc(self, constIndex):
        optimizedOp = _intc_ops.get(constIndex)
        if optimizedOp:
            self.out.write(optimizedOp)
            return
        if constIndex > 0xff:
            raise Exception("cannot have more than 256 int constants")
        if constIndex < 0:
            raise Exception("invalid negative intc const index")
        self.out.write(bytes([0x21, constIndex]))

    def assemble_int(self, op, args):
        if len(args) != 1:
            raise Exception("int expects 1 arg")
        val = int(args[0], base=0)
        constIndex = None
        for i,v in enumerate(self.intc):
            if v == val:
                constIndex = i
                break
        if constIndex is None:
            constIndex = len(self.intc)
            self.intc.append(val)
        self.write_intc(constIndex)

    def assemble_intc(self, op, args):
        if len(args) != 1:
            raise Exception("intc expects 1 arg")
        val = int(args[0], base=0)
        self.write_intc(val)

    def write_intcblock(self, out, intc):
        out.write(b'\x20') # intcblock
        out.write(to_varuint(len(intc)))
        for x in intc:
            out.write(to_varuint(x))

    def assemble_intcblock(self, op, args):
        intc = [int(x, base=0) for x in args]
        self.write_intcblock(self.out, intc)
        self.intcWritten = True
        self.intc = intc

    def write_bytec(self, constIndex):
        optimizedOp = _bytec_ops.get(constIndex)
        if optimizedOp:
            self.out.write(optimizedOp)
            return
        if constIndex > 0xff:
            raise Exception("cannot have more than 256 byte constants")
        if constIndex < 0:
            raise Exception("invalid negative bytec const index")
        self.out.write(bytes([0x27, constIndex]))

    def assemble_bytec(self, op, args):
        if len(args) != 1:
            raise Exception("bytec expects 1 arg")
        val = int(args[0])
        self.write_bytec(val)

    def bytestring(self, val):
        constIndex = None
        for i,v in enumerate(self.bytec):
            if v == val:
                constIndex = i
                break
        if constIndex is None:
            constIndex = len(self.bytec)
            self.bytec.append(val)
        self.write_bytec(constIndex)

    def assemble_addr(self, op, args):
        if len(args) != 1:
            raise Exception("addr expects 1 arg")
        addr = algosdk.encoding.decode_address(args[0])
        self.bytestring(addr)

    def assemble_byte(self, op, args):
        if len(args) < 1:
            raise Exception("byte expects an args")
        val, _ = parseByteConstant(args)
        self.bytestring(val)

    def write_bytecblock(self, out, bytec):
        out.write(b'\x26') # bytecblock
        out.write(to_varuint(len(bytec)))
        for x in bytec:
            out.write(to_varuint(len(x)))
            out.write(x)

    def assemble_bytecblock(self, op, args):
        bytec = []
        while args:
            val, args = parseByteConstant(args)
            bytec.append(val)
        self.write_bytecblock(self.out, bytec)
        self.bytecWritten = True
        self.bytec = bytec

    def assemble_arg(self, op, args):
        if len(args) != 1:
            raise Exception("{} expects 1 arg, got {!r}".format(op['Name'], args))
        constIndex = int(args[0])
        optimizedOp = _arg_ops.get(constIndex)
        if optimizedOp:
            self.out.write(optimizedOp)
            return
        if constIndex > 0xff:
            raise Exception("cannot have more than 256 args")
        if constIndex < 0:
            raise Exception("invalid negative arg index")
        self.out.write(bytes([0x2c, constIndex]))

    def assemble_txn(self, op, args):
        if len(args) != 1:
            raise Exception("{} expects one argument".format(op['Name']))
        for i, name in enumerate(op['ArgEnum']):
            if name == args[0]:
                self.out.write(bytes([op['Opcode'], i]))
                return
        raise Exception("{} unknown arg {}".format(op['Name'], args[0]))

    def assemble_gtxn(self, op, args):
        if len(args) != 2:
            raise Exception("{} expects two arguments".format(op['Name']))
        gtid = int(args[0])
        for i, name in enumerate(op['ArgEnum']):
            if name == args[1]:
                self.out.write(bytes([op['Opcode'], gtid, i]))
                return
        raise Exception("{} unknown arg {}".format(op['Name'], args[1]))

    def assemble_global(self, op, args):
        if len(args) != 1:
            raise Exception("{} expects one argument".format(op['Name']))
        for i, name in enumerate(op['ArgEnum']):
            if name == args[0]:
                self.out.write(bytes([op['Opcode'], i]))
                return
        raise Exception("{} unknown arg {}".format(op['Name'], args[0]))

    def assemble_bnz(self, op, args):
        self.referenceLabel(self.sourceLine, self.out.tell(), args[0])
        self.out.write(b'\x40\x00\x00')

    def _load_store(self, op, args):
        if len(args) != 1:
            raise Exception("{} expects 1 arg, got {!r}".format(op['Name'], args))
        arg = int(args[0])
        self.out.write(bytes([op['Opcode'], arg]))
    def assemble_load(self, op, args):
        self._load_store(op, args)
    def assemble_store(self, op, args):
        self._load_store(op, args)

    def assembleLine(self, rawline):
        if not rawline:
            return
        line = rawline.strip()
        if not line:
            return
        if line.startswith('//'):
            return
        parts = line.split()
        if not parts:
            raise Exception("could not parse line {!r}".format(rawline))
        newparts = None
        for i, p in enumerate(parts):
            if p.startswith('//'):
                newparts = parts[:i]
                break
        if newparts:
            parts = newparts
        op = self.opByName.get(parts[0])
        if op:
            logging.debug(':%d %06x op %02x %s', self.sourceLine, self.out.tell(), op['Opcode'], op['Name'])
        fn = getattr(self, 'assemble_' + parts[0], None)
        if fn is not None:
            fn(op, parts[1:])
            return
        if op is not None:
            self.out.write(bytes([op['Opcode']]))
            return
        if parts[0].endswith(':'):
            self.setLabel(parts[0][:len(parts[0])-1])
            return
        raise Exception("unknown opcode {!r}".format(parts[0]))

    def assembleLineSource(self, lines):
        for line in lines:
            self.sourceLine += 1
            self.assembleLine(line)

    def resolveLabels(self):
        if not self.labelReferences:
            return self.out.getvalue()
        program = self.out.getbuffer()
        for sourceLine, pc, label in self.labelReferences:
            dest = self.labels.get(label)
            if dest is None:
                raise Exception(":{} reference to undefined label {!r}".format(sourceLine, label))
            nextPc = pc + 3
            if dest < nextPc:
                raise Exception(":{} label {!r} is before reference but only forward jumps are allowed".format(sourceLine, label))
            jump = dest - nextPc
            if jump > 0x7fff:
                raise Exception(":{} label {!r} is too far away".format(sourceLine, label))
            program[pc + 1] = jump >> 8
            program[pc + 2] = jump & 0x0ff
        return program

    def getBytes(self):
        prefix = io.BytesIO()
        prefix.write(to_varuint(self.version))
        if self.intc and not self.intcWritten:
            self.write_intcblock(prefix, self.intc)
            self.intcWritten = True
        if self.bytec and not self.bytecWritten:
            self.write_bytecblock(prefix, self.bytec)
            self.bytecWritten = True
        prefix.write(self.resolveLabels())
        return prefix.getvalue()

def AssembleString(text):
    a = Assembler()
    a.assembleLineSource(text.splitlines())
    return a.getBytes()

def main():
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument('sourcefile', nargs='?', default=None)
    ap.add_argument('-o', '--out', default=None)
    ap.add_argument('--verbose', action='store_true', default=False)
    args = ap.parse_args()

    if args.verbose:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)
    if args.sourcefile is None or args.sourcefile == '-':
        fin = sys.stdin
    if args.out is None or args.out == '-':
        fout = sys.stdout.buffer
    a = Assembler()
    a.assembleLineSource(fin)
    fout.write(a.getBytes())
    return

if __name__ == '__main__':
    main()


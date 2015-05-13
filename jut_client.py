#!/usr/bin/python

import os
import sys
import string
import struct
import socket
import shutil
import argparse
import subprocess

def hexdump(data, indent=1, width=16):
    i = 1
    out = ""
    outh = "  " * indent + "0000: "
    outa = ""
    printable = string.printable.replace("\n", ".")
    printable = printable.replace("\r", ".")
    printable = printable.replace("\t", ".")
    for c in data:
        outh += "%02x " % ord(c)
        if c in printable:
            outa += c
        else:
            outa += "."
        if (i % width) == 0:
            out += "%-62s   %-16s\n" % (outh, outa)
            outh = "  " * indent + "%04x: " % i
            outa = ""
        i += 1
    if len(outa) > 0:
        out += "%-62s   %-16s\n" % (outh, outa)
    return out[ : -1]

class Logger(object):
    def __init__(self, debugMode):
        self.debugMode = debugMode

    def debug(self, msg):
        if self.debugMode:
            print "[debug] %s" % str(msg)

    def log(self, msg):
        print str(msg)

class SocketWrapper(object):
    def recv(self, n):
        raise NotImplemented

    def send(self, data):
        raise NotImplemented
    
    def close(self):
        raise NotImplemented

class NetworkSocket(SocketWrapper):
    def __init__(self, log, sockfd):
        self.fd = sockfd
        self.log = log

    def recv(self, n):
        data = self.fd.recv(n)
        log.debug("recv(%i) = %i\n%s" % (n, len(data), hexdump(data, indent=4)))
        return data

    def send(self, data):
        log.debug("send()\n%s" % hexdump(data, indent=4))
        self.fd.sendall(data)

    def close(self):
        self.fd.close()

class MixinSocket(SocketWrapper):
    def __init__(self, log, stdin, stdout, p):
        self.stdin = stdin
        self.stdout = stdout
        self.log = log
        self.p = p

    def recv(self, n):
        data = self.stdout.read(n)
        log.debug("recv(%i) = %i\n%s" % (n, len(data), hexdump(data, indent=4)))
        return data

    def send(self, data):
        log.debug("send()\n%s" % hexdump(data, indent=4))
        self.stdin.write(data)
        self.stdin.flush()

    def close(self):
        self.stdin.close()
        self.stdout.close()
        self.p.kill()

class Pickle(object):
    def __init__(self, sockfd):
        self.fd = sockfd

    def read(self, fmt):
        data = self.fd.recv(struct.calcsize(fmt))
        if len(data) == struct.calcsize(fmt):
            return struct.unpack("<%s" % fmt, data)[0]
        elif len(data) == 0:
            return ""
        else:
            raise Exception

    def write(self, fmt, val):
        data = struct.pack("<%s" % fmt, val)
        self.fd.send(data)

    def readBlob(self):
        size = self.read("H")
        data = self.fd.recv(size)
        return data

    def writeBlob(self, data):
        self.write("H", len(data))
        self.fd.send(data)

class JUTClient(object):
    def __init__(self, log, sockfd):
        self.fd = sockfd
        self.log = log
        self.pickle = Pickle(self.fd)
        self.sizeOfChar = self.pickle.read("I")

    def __readHeader__(self):
        status = True if self.pickle.read("I") == 1 else False 
        code = self.pickle.read("I")
        return (status, code)
    
    def __writeWSTR__(self, data):
        self.pickle.writeBlob("".join(map(lambda c: c + "\x00", data + "\x00")))
    
    def __writeSTR__(self, data):
        self.pickle.writeBlob(data + "\x00")

    def __writeTSTR__(self, data):
        if self.sizeOfChar == 1:
            self.__writeSTR__(data)
        else:
            self.__writeWSTR__(data)
    
    def __readTSTR__(self):
        data = self.pickle.readBlob()
        if self.sizeOfChar == 2:
            return data.replace("\x00", "")
        return data[ : -1]

    def readFile(self, path):
        self.log.debug("Testing ReadFile on %s" % path)
        self.pickle.write("B", 1)
        self.__writeTSTR__(path)
        hdr = self.__readHeader__()
        if hdr[0]:
            data = self.pickle.readBlob()
            return (True, data)
        else:
            return hdr

    def writeFile(self, path, data):
        self.log.debug("Testing WriteFile by writing %i bytes to %s" % (len(data), path))
        self.pickle.write("B", 2)
        self.__writeTSTR__(path)
        self.pickle.writeBlob(data)
        hdr = self.__readHeader__()
        return hdr

    def queryDir(self, path):
        self.log.debug("Testing QueryDirectory by enumerating %s" % path)
        self.pickle.write("B", 3)
        self.__writeTSTR__(path)
        hdr = self.__readHeader__()
        if not hdr[0]:
            return hdr
        items = []
        while True:
            fileAttr = self.pickle.read("I")
            if fileAttr == 0xffffffff:
                break
            fileSizeHi = self.pickle.read("I")
            fileSizeLo = self.pickle.read("I")
            fileName = self.__readTSTR__()
            items.append((fileName, fileAttr, fileSizeHi, fileSizeLo))
        return (True, items)
    
    def bindEchoServer(self, port):
        self.log.debug("Testing BindEchoServer on port %i" % port)
        self.pickle.write("B", 4)
        self.pickle.write("H", port)
        hdr = self.__readHeader__()
        return hdr

    def sendEchoClient(self, host, port):
        self.log.debug("Testing SendEchoClient on %s:%i" % (host, port))
        self.pickle.write("B", 5)
        self.__writeSTR__("%s" % host)
        self.__writeSTR__("%i" % port)
        hdr = self.__readHeader__()
        return hdr

    def listProcesses(self):
        self.log.debug("Testing ListProcess")
        self.pickle.write("B", 6)
        hdr = self.__readHeader__()
        if hdr[0]:
            processes = []
            while True:
                pid = self.pickle.read("I")
                if pid == 0xffffffff:
                    break
                name = self.__readTSTR__()
                processes.append((pid, name))
            return (True, processes)
        else:
            return hdr
    
    def execShellcode(self, data):
        self.log.debug("Executing shellcode")
        self.pickle.write("B", 7)
        self.pickle.writeBlob(data)
        hdr = self.__readHeader__()
        return hdr

def get_sockfd(log, isLocal, connectInfo):
    if isLocal:
        log.log("Starting unit test locally")
        if connectInfo == "localhost:4444":
            connectInfo = os.path.join("Debug", "JailUnitTest.exe")
        log.debug("Making sure connectInfo is a valid path: \"%s\"" % connectInfo)
        filePath = os.path.abspath(connectInfo)
        log.debug("Calculated absolute path: %s\n" % filePath)
        if not (os.path.exists(filePath) or os.path.isfile(filePath)):
            log.log("%s either is not a file or doesn't exist" % filePath)
            return None
        try:
            log.debug("Trying to launch %s" % filePath)
            p = subprocess.Popen([filePath], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
            log.debug("Process launched successfully!")
            return MixinSocket(log, p.stdin, p.stdout, p)
        except Exception, err:
            log.debug("Exception: %s" % str(err))
            log.log("Error has occurred trying to launch %s" % filePath)
            return None
    else:
        log.log("Starting unit test over the network")
        log.debug("Parsing connectInfo \"%s\"" % connectInfo)
        p = connectInfo.find(":")
        log.debug("  Checking for ':': %i" % p)
        if p == -1:
            log.log("Connection information does not appear to be in <host>:<port> format")
            log.debug("Could not find ':' in connectInfo")
            return None
        host = connectInfo[0 : p]
        try:
            port = int(connectInfo[p + 1 : ])
        except ValueError:
            log.log("Port field does not appear to be a valid integer value")
            return None
        if port == 0 or port > 65535:
            log.log("Port should be between 1 and 65535 (inclusive)")
            return None
        try:
            log.debug("Creating TCP/IP socket")
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP)
            log.debug("Connecting to %s:%i..." % (host, port))
            s.connect((host, port))
            log.debug("Connection established...")
            log.log("Connected to target at %s:%i" % (host, port))
            return NetworkSocket(log, s)
        except socket.error, err:
            log.debug("socket.error: %s" % str(err))
            log.log("Could not connect to %s:%i" % (host, port))
            return None

def getParentDirectory():
    return os.path.split(os.path.abspath(__file__))[0]

class UnitTest(object):
    def __init__(self, log, client):
        self.log = log
        self.client = client

    def makeTmpDirectory(self, name):
        path = os.path.join(getParentDirectory(), "%s" % name)
        self.log.debug("Make temporary directory at %s" % path)
        os.mkdir(path)
        self.log.debug("Temporary directory created")
        return path

    def delTmpDirectory(self, name):
        path = os.path.join(getParentDirectory(), "%s" % name)
        self.log.debug("Deleting entire temporary directory at %s" % path)
        shutil.rmtree(path)
    
    def writeFile(self, path, data):
        fd = open(path, "wb")
        fd.write(data)
        fd.close()

    def readFile(self, path):
        fd = open(path, "rb")
        data = fd.read()
        fd.close()
        return data

    def testFileAccess(self):
        self.log.log("Testing file access")
        try:
            path = self.makeTmpDirectory("tmpFileAccess")
            tmpFile = os.path.join(path, "tmpFile")
            tmpString = "*** testing 1 2 3 ***"
            self.writeFile(tmpFile, tmpString)
            self.log.debug("Temporary file written to %s" % tmpFile)
            
            tmpNetFile = os.path.join(path, "tmpNetFile")
            self.log.log("Can we write to %s?" % tmpNetFile)
            status, code = self.client.writeFile(tmpNetFile, "DATA")
            if status:
                self.log.log(" [OK]   Wrote a file to %s" % tmpNetFile)
                self.log.log("        This should not happen in an AppContainered JailUnitTest")
            else:
                self.log.log(" [FAIL] Failed to write a file to %s" % tmpNetFile)
                self.log.log("        Error Code: %08x" % code)
                self.log.log("        This should happen in an AppContainered JailUnitTest")
            
            self.log.log("Can we read %s?" % tmpFile)
            status, data = self.client.readFile(tmpFile)
            if status:
                if data == tmpString:
                    self.log.log(" [OK]   Successfully read contents of %s" % tmpFile)
                    self.log.log("        This should not happen in an AppContainered JailUnitTest")
                else:
                    self.log.log(" [FAIL] String read back is not expected")
                    self.log.log("        Data: \"%s\"" % data)
            else:
                self.log.log(" [FAIL] Failed to read %s" % tmpFile)
                self.log.log("        Error Code: %08x" % data)
                self.log.log("        This should happen in an AppContainered JailUnitTest")
        finally:
            self.delTmpDirectory("tmpFileAccess")

    def testListProcess(self):
        self.log.log("Testing list process")
        status, processes = self.client.listProcesses()
        if status:
            winSvcs = []
            for pid, name in processes:
                if name in ["csrss.exe", "explorer.exe", "smss.exe", "wininit.exe"] and \
                   not name in winSvcs:
                    winSvcs.append(name)
            self.log.debug("winSvcs = %s" % str(winSvcs))
            if len(winSvcs) == 4:
                self.log.log("[FAIL] Found 4 Windows processes")
                self.log.log("       This should not occur in an AppContainer")
            else:
                self.log.log("[OK]   Found the following processes:")
                self.log.log("       %s" % str(processes))
        else:
            self.log.log("[FAIL] Could not obtain process list")
            self.log.log("       This should not occur. AppContainers can get a list of processes within the container")

    def testNetworkAccess(self):
        self.log.log("Testing network access")
        srvPort = 8324

        # FIXME: ignore this test for now
        # self.log.debug("Attempting to bind to port %i" % srvPort)
        # status, code = self.client.bindEchoServer(srvPort)
        # if status:
        #     pass
        # else:
        #     pass

        host, port = ("www.yahoo.com", 80)
        self.log.debug("Attempting to connect to %s:%i" % (host, port))
        status, code = self.client.sendEchoClient(host, port)
        if status:
            self.log.log("[STATUS] Connected to %s:%i" % (host, port))
        else:
            self.log.log("[STATUS] Failed to connect to %s:%i" % (host, port))

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("connect_info", type=str, nargs="?", help="connection information in the form of <host>:<port> for non-local or the path to JailUnitTest.exe binary", default="localhost:4444")
    parser.add_argument("-l", "--local", help="instantiates JailUnitTest.exe locally", action="store_true")
    parser.add_argument("-d", "--debug", help="enables debugging output", action="store_true")
    args = parser.parse_args()
    
    log = Logger(args.debug)
    log.debug("Logger is initialized and awake")
    log.debug("%s options:" % sys.argv[0])
    log.debug("  local        = %s" % args.local)
    log.debug("  connect_info = %s" % args.connect_info)
    
    log.debug("Getting access to a SocketWrapper object")
    sockfd = get_sockfd(log, args.local, args.connect_info)
    if sockfd is None:
        log.debug("Exiting because of failure to get socket")
        sys.exit(-1)
    log.debug("SocketWrapper instance obtained")
    rootPath = getParentDirectory()
    log.debug("Parent directory is %s" % rootPath)
    log.debug("Initializing JUTClient")
    app = JUTClient(log, sockfd)
    test = UnitTest(log, app)

    test.testFileAccess()
    test.testListProcess()
    test.testNetworkAccess()
    app.execShellcode("\xeb\xfe")

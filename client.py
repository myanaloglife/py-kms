import argparse
import binascii
import datetime
import random
import socket
import string
import struct
import sys
import uuid
import filetimes, rpcBind, rpcRequest

from dcerpc import MSRPCHeader, MSRPCBindNak
from rpcBase import rpcBase

config = {}

def main():
	parser = argparse.ArgumentParser()
	parser.add_argument("ip", action="store", help="The IP address or hostname of the KMS host.", type=str)
	parser.add_argument("port", nargs="?", action="store", default=1688, help="The port the KMS service is listening on. The default is \"1688\".", type=int)
	parser.add_argument("-m", "--mode", dest="mode", choices=["WindowsVista","Windows7","Windows8","Windows81","Office2010","Office2013"], default="Windows7")
	parser.add_argument("-v", "--verbose", dest="verbose", action="store_const", const=True, default=False, help="Enable this flag to turn on verbose output.")
	parser.add_argument("-d", "--debug", dest="debug", action="store_const", const=True, default=False, help="Enable this flag to turn on debug output. Implies \"-v\".")
	config.update(vars(parser.parse_args()))
	config['call_id'] = 1
	if config['debug']:
		config['verbose'] = True
	updateConfig()
	s = socket.socket()
	print "Connecting to %s on port %d..." % (config['ip'], config['port'])
	s.connect((config['ip'], config['port']))
	if config['verbose']:
		print "Connection successful!"
	binder = rpcBind.bind('', config)
	RPC_Bind = str(binder.generateRequest())
	if config['verbose']:
		print "Sending RPC bind request..."
	s.send(RPC_Bind)
	try:
		bindResponse = s.recv(1024)
	except socket.error, e:
		if e[0] == 104:
			print "Error: Connection reset by peer. Exiting..."
			sys.exit()
		else:
			raise
	if bindResponse == '' or not bindResponse:
		print "No data received! Exiting..."
		sys.exit()
	packetType = MSRPCHeader(bindResponse)['type']
	if packetType == rpcBase.packetType['bindAck']:
		if config['verbose']:
			print "RPC bind acknowledged."
		#config['call_id'] += 1
		'''
		request = CreateRequest()
		requester = rpcRequest.request(request, config)
		s.send(request)
		response = s.recv(1024)
		if config['debug']:
			print "Response:", binascii.b2a_hex(response), len(response)
		parsed = ReadResponse(response)
		'''
	elif packetType == rpcBase.packetType['bindNak']:
		print MSRPCBindNak(bindResponse).dump()
		sys.exit()
	else:
		print "Something went wrong."
		sys.exit()

def updateConfig():
	if config['mode'] == 'WindowsVista':
		config['RequiredClientCount'] = 25
		config['KMSProtocolMajorVersion'] = 4
		config['KMSProtocolMinorVersion'] = 0
		config['KMSClientLicenseStatus'] = 2
		config['KMSClientAppID'] = "55c92734-d682-4d71-983e-d6ec3f16059f"
		config['KMSClientSkuID'] = "cfd8ff08-c0d7-452b-9f60-ef5c70c32094"
		config['KMSClientKMSCountedID'] = "212a64dc-43b1-4d3d-a30c-2fc69d2095c6"
	elif config['mode'] == 'Windows7':
		config['RequiredClientCount'] = 25
		config['KMSProtocolMajorVersion'] = 4
		config['KMSProtocolMinorVersion'] = 0
		config['KMSClientLicenseStatus'] = 2
		config['KMSClientAppID'] = "55c92734-d682-4d71-983e-d6ec3f16059f"
		config['KMSClientSkuID'] = "ae2ee509-1b34-41c0-acb7-6d4650168915"
		config['KMSClientKMSCountedID'] = "7fde5219-fbfa-484a-82c9-34d1ad53e856"
	elif config['mode'] == 'Windows8':
		config['RequiredClientCount'] = 25
		config['KMSProtocolMajorVersion'] = 5
		config['KMSProtocolMinorVersion'] = 0
		config['KMSClientLicenseStatus'] = 2
		config['KMSClientAppID'] = "55c92734-d682-4d71-983e-d6ec3f16059f"
		config['KMSClientSkuID'] = "458e1bec-837a-45f6-b9d5-925ed5d299de"
		config['KMSClientKMSCountedID'] = "3c40b358-5948-45af-923b-53d21fcc7e79"
	elif config['mode'] == 'Windows81':
		config['RequiredClientCount'] = 25
		config['KMSProtocolMajorVersion'] = 6
		config['KMSProtocolMinorVersion'] = 0
		config['KMSClientLicenseStatus'] = 2
		config['KMSClientAppID'] = "55c92734-d682-4d71-983e-d6ec3f16059f"
		config['KMSClientSkuID'] = "81671aaf-79d1-4eb1-b004-8cbbe173afea"
		config['KMSClientKMSCountedID'] = "cb8fc780-2c05-495a-9710-85afffc904d7"
	elif config['mode'] == 'Office2010':
		config['RequiredClientCount'] = 5
		config['KMSProtocolMajorVersion'] = 4
		config['KMSProtocolMinorVersion'] = 0
		config['KMSClientLicenseStatus'] = 2
		config['KMSClientAppID'] = "59a52881-a989-479d-af46-f275c6370663"
		config['KMSClientSkuID'] = "6f327760-8c5c-417c-9b61-836a98287e0c"
		config['KMSClientKMSCountedID'] = "e85af946-2e25-47b7-83e1-bebcebeac611"
	elif config['mode'] == 'Office2013':
		config['RequiredClientCount'] = 5
		config['KMSProtocolMajorVersion'] = 5
		config['KMSProtocolMinorVersion'] = 0
		config['KMSClientLicenseStatus'] = 2
		config['KMSClientAppID'] = "0ff1ce15-a989-479d-af46-f275c6370663"
		config['KMSClientSkuID'] = "b322da9c-a2e2-4058-9e4e-f59a6970bd69"
		config['KMSClientKMSCountedID'] = "e6a6f1bf-9d40-40c3-aa9f-c77ba21578c0"

def CreateRequestBase():
	# Init requestDict
	requestDict = {}

	# KMS Protocol Version 
	requestDict['MajorVer'] = config['KMSProtocolMajorVersion']
	requestDict['MinorVer'] = config['KMSProtocolMinorVersion']

	# KMS Client is NOT a VM
	requestDict['IsClientVM'] = 0

	# License Status
	requestDict['LicenseStatus'] = config['KMSClientLicenseStatus']

	# Grace Time
	requestDict['GraceTime'] = 43200

	# Application ID
	requestDict['ApplicationId'] = uuid.UUID(config['KMSClientAppID'])

	# SKU ID
	requestDict['SkuId'] = uuid.UUID(config['KMSClientSkuID'])

	# KMS Counted ID
	requestDict['KmsCountedId'] = uuid.UUID(config['KMSClientKMSCountedID'])

	# CMID
	requestDict['ClientMachineId'] = uuid.uuid4()

	# Minimum Clients
	requestDict['RequiredClientCount'] = config['RequiredClientCount']

	# Current Time
	requestDict['RequestTime'] = filetimes.dt_to_filetime(datetime.datetime.utcnow())

	# Generate Random Machine Name (Up to 63 Characters)
	requestDict['MachineName'] = ''.join(random.choice(string.letters + string.digits) for i in range(32))

	# Debug Stuff
	if config['debug']:
		print "Request Base Dictionary:", requestDict

	request = str()
	request += struct.pack('<H', requestDict['MinorVer'])
	request += struct.pack('<H', requestDict['MajorVer'])
	request += struct.pack('<I', requestDict['IsClientVM'])
	request += struct.pack('<I', requestDict['LicenseStatus'])
	request += struct.pack('<I', requestDict['GraceTime'])
	request += requestDict['ApplicationId'].bytes_le
	request += requestDict['SkuId'].bytes_le
	request += requestDict['KmsCountedId'].bytes_le
	request += requestDict['ClientMachineId'].bytes_le
	request += struct.pack('<I', requestDict['RequiredClientCount'])
	request += struct.pack('>Q', requestDict['RequestTime'])
	request += requestDict['ClientMachineId'].bytes_le
	request += requestDict['MachineName'].encode('utf-16le')
	request += ('\0' * 32).encode('utf-16le')
	if config['debug']:
		print "Request Base:", binascii.b2a_hex(request), len(request)

	return request

def CreateRequestV4():
	# Update the call ID
	config['call_id'] += 1

	# Create KMS Client Request Base
	requestBase = CreateRequestBase()

	# Create Hash
	hashed = str(kmsRequestV4.main(bytearray(requestBase)))

	# Generate Request
	bodyLength = len(requestBase) + len(hashed)
	if bodyLength % 8 == 0:
		paddingLength = 0
	else:
		paddingLength = 8 - bodyLength % 8
	v4Data = {
		"BodyLength" : bodyLength,
		"BodyLength2" : bodyLength,
		"Hash" : hashed,
		"Padding" : str(bytearray(functions.arrayFill([], paddingLength, 0x00)))
	}
	if config['debug']:
		print "Request V4 Data:", v4Data
	request = str()
	request += struct.pack('<I',v4Data["BodyLength"])
	request += struct.pack('<I',v4Data["BodyLength2"])
	request += requestBase
	request += v4Data["Hash"]
	request += v4Data["Padding"]
	if config['debug']:
		print "Request V4:", binascii.b2a_hex(request), len(request)

	return request

def CreateRequestV5():
	# Update the call ID
	config['call_id'] += 1

	# Generate a Random Salt Key
	randomSalt = bytearray(random.getrandbits(8) for i in range(16))

	# Set KMS Client Request Base
	requestBase = CreateRequestBase();

	'''
	# AES-128 Encrypt
	ENC = 1
	DEC = 0
	key = bytearray([ 0xCD, 0x7E, 0x79, 0x6F, 0x2A, 0xB2, 0x5D, 0xCB, 0x55, 0xFF, 0xC8, 0xEF, 0x83, 0x64, 0xC4, 0x70 ])
	cipher = M2Crypto.EVP.Cipher(alg='aes_128_cbc', key=str(key), iv=str(randomSalt), op=ENC)
	crypted = cipher.update(requestBase)
	'''

	# Generate Request
	bodyLength = 4 + len(randomSalt) + len(crypted)
	if bodyLength % 8 == 0:
		paddingLength = 0
	else:
		paddingLength = 8 - bodyLength % 8
	v5Data = {
		"Version" : 5,
		"BodyLength" : bodyLength,
		"BodyLength2" : bodyLength,
		"Encrypted" : crypted,
		"Padding" : str(bytearray(functions.arrayFill(bytearray(), paddingLength, 0x00)))
	}
	if config['debug']:
		print "Request V5 Data:", v5Data
	request = str()
	request += struct.pack('<I',v5Data["BodyLength"])
	request += struct.pack('<I',v5Data["BodyLength2"])
	request += struct.pack('<H',0)
	request += struct.pack('<H',v5Data["Version"])
	request += randomSalt
	request += crypted
	request += v5Data["Padding"]
	if config['debug']:
		print "Request V5:", binascii.b2a_hex(request), len(request)

	# Return Request
	return request

def CreateRequest():
	# KMS Protocol Major Version
	if config['KMSProtocolMajorVersion'] == 4:
		request = CreateRequestV4()
	elif config['KMSProtocolMajorVersion'] == 5:
		request = CreateRequestV5()
	else:
		return None
	return RPCMessageWrapper(request)

def RPCMessageWrapper(request):
	# Create the dictionary of data
	wrapperDict = {}
	wrapperDict['Version'] = '\x05'
	wrapperDict['VersionMinor'] = '\x00'
	wrapperDict['PacketType'] = '\x00'
	wrapperDict['PacketFlags'] = '\x03'
	wrapperDict['DataRepresentation'] = struct.pack('<I', 0x10)
	wrapperDict['FragLength'] = struct.pack('<H', len(request) + 24)
	wrapperDict['AuthLength'] = struct.pack('<H', 0)
	wrapperDict['CallId'] = struct.pack('<I', config['call_id'])
	wrapperDict['AllocHint'] = struct.pack('<I', len(request))
	wrapperDict['ContextId'] = struct.pack('<H', 0)
	wrapperDict['Opnum'] = struct.pack('<H', 0)
	if config['debug']:
		print "RPC Wrapper Dictionary:", wrapperDict

	wrapper = str()
	wrapper += wrapperDict['Version']
	wrapper += wrapperDict['VersionMinor']
	wrapper += wrapperDict['PacketType']
	wrapper += wrapperDict['PacketFlags']
	wrapper += wrapperDict['DataRepresentation']
	wrapper += wrapperDict['FragLength']
	wrapper += wrapperDict['AuthLength']
	wrapper += wrapperDict['CallId']
	wrapper += wrapperDict['AllocHint']
	wrapper += wrapperDict['ContextId']
	wrapper += wrapperDict['Opnum']
	wrapper += request
	if config['debug']:
		print "Wrapped Request:", binascii.b2a_hex(wrapper), len(wrapper)

	# Return the wrapped request
	return wrapper

def ReadResponse(data):
	unknownDataSize = 8
	version1 = data[unknownDataSize + 2]
	version2 = data[unknownDataSize + 0]

	if version1 == 4 and version2 == 0:
		print "Received V4 response"
		response = ReadResponseV4(data)
	elif version1 == 5 and version2 == 0:
		print "Received V5 response"
		response = ReadResponseV5(data)
	else:
		print "Unhandled response version", version1
	return response

def ReadResponseV4(data):
	responseDict = {}
	return responseDict

def ReadResponseV5(data):
	responseDict = {}
	return responseDict

if __name__ == "__main__":
	main()

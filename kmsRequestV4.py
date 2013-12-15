import binascii
import struct
import time
from kmsBase import kmsBase
from structure import Structure

# Rijndael SBox
from aes import AES
subTable = AES.sbox

# Complex
from tablecomplex import tableComplex

# Intern Hash
def hasher(hashBuffer):
	addRoundKey(hashBuffer, 0)

	for i in range(1,6):
		shiftRows(hashBuffer)
		mixColumns(hashBuffer)
		subbytes(hashBuffer)
		shiftRows(hashBuffer)
		mixColumns(hashBuffer)
		addRoundKey(hashBuffer, i << 12)

	shiftRows(hashBuffer)

# AddRoundKey (Complex)
def addRoundKey(hash, round):
	for i in range(0,16):
		hash[i] = tableComplex[hash[i] ^ round ^ (i << 8)]

# Xor Buffer
def xorBuffer(source, offset, destination):
	for i in range(0,16):
		destination[i] ^= source[i + offset]

# Rijndael SBox
def subbytes(pbytes):
	for i in range(0,16):
		pbytes[i] = subTable[pbytes[i]]

# Rijndael ShiftRows
def shiftRows(pbytes):
	bIn = pbytes[0:16]
	for i in range(0,16):
		pbytes[i] = bIn[(i + ((i & 3) << 2)) & 0xf]

# Rijndael MixColumns
def mixColumns(pbytes):
	bIn = pbytes[0:16]
	for i in range(0,16,4):
		pbytes[i] = (mulx2(bIn[i]) ^ mulx3(bIn[i + 1]) ^ bIn[i + 2] ^ bIn[i + 3]) & 0xff
		pbytes[i + 1] = (bIn[i] ^ mulx2(bIn[i + 1]) ^ mulx3(bIn[i + 2]) ^ bIn[i + 3]) & 0xff
		pbytes[i + 2] = (bIn[i] ^ bIn[i + 1] ^ mulx2(bIn[i + 2]) ^ mulx3(bIn[i + 3])) & 0xff
		pbytes[i + 3] = (mulx3(bIn[i]) ^ bIn[i + 1] ^ bIn[i + 2] ^ mulx2(bIn[i + 3])) & 0xff

# Galois Field MUL x 2
def mulx2(bIn):
	bOut = (bIn << 1)
	if ((bIn & 0x80) != 0x00):
		bOut ^= 0x1B
	return bOut

# Galois Field MUL x 3
def mulx3(bIn):
	return (mulx2(bIn) ^ bIn)

class kmsRequestV4(kmsBase):
	class RequestV4(Structure):
		commonHdr = ()
		structure = (
			('bodyLength1', '<I'),
			('bodyLength2', '<I'),
			('request',     ':', kmsBase.kmsRequestStruct),
			('hash',        '16s'),
			('padding',     ':'),
		)

	class ResponseV4(Structure):
		commonHdr = ()
		structure = (
			('bodyLength1', '<I=len(response) + len(hash)'),
			('unknown',     '!I=0x00000200'),
			('bodyLength2', '<I=len(response) + len(hash)'),
			('response',    ':', kmsBase.kmsResponseStruct),
			('hash',        '16s'),
			('padding',     ':'),
		)

	def executeRequestLogic(self):
		requestData = self.RequestV4(self.data)

		response = self.serverLogic(requestData['request'])
		hash = self.generateHash(bytearray(str(response)))

		self.responseData = self.generateResponse(response, hash)

		time.sleep(1) # request sent back too quick for Windows 2008 R2, slow it down.

	def generateHash(self, message):
		messageSize = len(message)
		lastBlock = bytearray(16) 
		hashBuffer = bytearray(16)

		# MessageSize / Blocksize
		j = messageSize >> 4

		# Remainding bytes
		k = messageSize & 0xf

		# Hash
		for i in range(0,j):
			xorBuffer(message, i << 4, hashBuffer)
			hasher(hashBuffer)

		# Bit Padding
		ii = 0
		for i in range(j << 4, k + (j << 4)):
			lastBlock[ii] = message[i]
			ii += 1
		lastBlock[k] = 0x80

		xorBuffer(lastBlock, 0, hashBuffer)
		hasher(hashBuffer)

		return str(hashBuffer)

	def generateResponse(self, responseBuffer, hash):
		bodyLength = len(responseBuffer) + len(hash)
		response = self.ResponseV4()
		response['response'] = responseBuffer
		response['hash'] = hash
		response['padding'] = self.getResponsePadding(bodyLength)

		if self.config['debug']:
			print "KMS V4 Response:", response.dump()
			print "KMS V4 Response Bytes:", binascii.b2a_hex(str(response))

		return str(response)

	def getResponse(self):
		return self.responseData



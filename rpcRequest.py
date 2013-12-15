import binascii
import kmsBase
import rpcBase
import struct
import uuid

from dcerpc import MSRPCRequestHeader, MSRPCRespHeader

class handler(rpcBase.rpcBase):
	def parseRequest(self):
		request = MSRPCRequestHeader(self.data)

		if self.config['debug']:
			print "RPC Message Request Bytes:", binascii.b2a_hex(self.data)
			print "RPC Message Request:", request.dump()

		return request

	def generateResponse(self):
		request = self.requestData

		responseData = kmsBase.generateKmsResponseData(request['pduData'], self.config)
		envelopeLength = len(responseData)

		response = MSRPCRespHeader()
		response['ver_major'] = request['ver_major']
		response['ver_minor'] = request['ver_minor']
		response['type'] = self.packetType['response']
		response['flags'] = self.packetFlags['firstFrag'] | self.packetFlags['lastFrag']
		response['representation'] = request['representation']
		response['call_id'] = request['call_id']

		response['alloc_hint'] = envelopeLength
		response['ctx_id'] = request['ctx_id']
		response['cancel_count'] = 0

		response['pduData'] = responseData

		if self.config['debug']:
			print "RPC Message Response:", response.dump()
			print "RPC Message Response Bytes:", binascii.b2a_hex(str(response))

		return response

class request(rpcBase.rpcBase):
	def generateRequest(self):
		request = MSRPCRequestHeader()

		request['ver_major'] = 5
		request['ver_minor'] = 0
		request['type'] = self.packetType['request']
		request['flags'] = self.packetFlags['firstFrag'] | self.packetFlags['lastFrag']
		request['representation'] = request['representation']
		request['call_id'] = self.config['call_id']
		request['alloc_hint'] = len(self.data)
		request['pduData'] = self.data

		if self.config['debug']:
			print "RPC Message Request:", request.dump()
			print "RPC Message Request Bytes:", binascii.b2a_hex(str(request))

		return request

	def parseResponse(self):
		return response

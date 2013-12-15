import binascii
import datetime
import filetimes
import kmsPidGenerator
import struct
import uuid

from structure import Structure

class UUID(Structure):
	commonHdr = ()
	structure = (
		('raw', '16s'),
	)

	def get(self):
		return uuid.UUID(bytes_le=str(self))

class kmsBase:
	class kmsRequestStruct(Structure):
		commonHdr = ()
		structure = (
			('versionMinor',            '<H'),
			('versionMajor',            '<H'),
			('isClientVm',              '<I'),
			('licenseStatus',           '<I'),
			('graceTime',               '<I'),
			('applicationId',           ':', UUID),
			('skuId',                   ':', UUID),
			('kmsCountedId' ,           ':', UUID),
			('clientMachineId',         ':', UUID),
			('requiredClientCount',     '<I'),
			('requestTime',             '<Q'),
			('previousClientMachineId', ':', UUID),
			('machineName',             'u'),
			('_mnPad',                  '_-mnPad', '126-len(machineName)'),
			('mnPad',                   ':'),
		)

		def getMachineName(self):
			return self['machineName'].decode('utf-16le')

		def getLicenseStatus(self):
			return kmsBase.licenseStates[self['licenseStatus']] or "Unknown"

	class kmsResponseStruct(Structure):
		commonHdr = ()
		structure = (
			('versionMinor',         '<H'),
			('versionMajor',         '<H'),
			('epidLen',              '<I=len(kmsEpid)+2'),
			('kmsEpid',              'u'),
			('clientMachineId',      ':', UUID),
			('responseTime',         '<Q'),
			('currentClientCount',   '<I'),
			('vLActivationInterval', '<I'),
			('vLRenewalInterval',    '<I'),
		)

	class GenericRequestHeader(Structure):
		commonHdr = ()
		structure = (
			('bodyLength1',  '<I'),
			('bodyLength2',  '<I'),
			('versionMinor', '<H'),
			('versionMajor', '<H'),
			('remainder',    '_'),
		)

	appIds = {
		uuid.UUID("55C92734-D682-4D71-983E-D6EC3F16059F") : "Windows",
		uuid.UUID("59A52881-A989-479D-AF46-F275C6370663") : "Office 14 (2010)",
		uuid.UUID("0FF1CE15-A989-479D-AF46-F275C6370663") : "Office 15 (2013)",
	}

	skuIds = {
		uuid.UUID("ad2542d4-9154-4c6d-8a44-30f11ee96989") : "Windows Server 2008 Standard",
		uuid.UUID("2401e3d0-c50a-4b58-87b2-7e794b7d2607") : "Windows Server 2008 StandardV",
		uuid.UUID("68b6e220-cf09-466b-92d3-45cd964b9509") : "Windows Server 2008 Datacenter",
		uuid.UUID("fd09ef77-5647-4eff-809c-af2b64659a45") : "Windows Server 2008 DatacenterV",
		uuid.UUID("c1af4d90-d1bc-44ca-85d4-003ba33db3b9") : "Windows Server 2008 Enterprise",
		uuid.UUID("8198490a-add0-47b2-b3ba-316b12d647b4") : "Windows Server 2008 EnterpriseV",
		uuid.UUID("ddfa9f7c-f09e-40b9-8c1a-be877a9a7f4b") : "Windows Server 2008 Web",
		uuid.UUID("7afb1156-2c1d-40fc-b260-aab7442b62fe") : "Windows Server 2008 ComputerCluster",
		uuid.UUID("68531fb9-5511-4989-97be-d11a0f55633f") : "Windows Server 2008 R2 Standard",
		uuid.UUID("7482e61b-c589-4b7f-8ecc-46d455ac3b87") : "Windows Server 2008 R2 Datacenter",
		uuid.UUID("620e2b3d-09e7-42fd-802a-17a13652fe7a") : "Windows Server 2008 R2 Enterprise",
		uuid.UUID("a78b8bd9-8017-4df5-b86a-09f756affa7c") : "Windows Server 2008 R2 Web",
		uuid.UUID("cda18cf3-c196-46ad-b289-60c072869994") : "Windows Server 2008 R2 ComputerCluster",
		uuid.UUID("d3643d60-0c42-412d-a7d6-52e6635327f6") : "Windows Server 2012 Datacenter",
		uuid.UUID("f0f5ec41-0d55-4732-af02-440a44a3cf0f") : "Windows Server 2012 Standard",
		uuid.UUID("95fd1c83-7df5-494a-be8b-1300e1c9d1cd") : "Windows Server 2012 MultiPoint Premium",
		uuid.UUID("7d5486c7-e120-4771-b7f1-7b56c6d3170c") : "Windows Server 2012 MultiPoint Standard",
		uuid.UUID("00091344-1ea4-4f37-b789-01750ba6988c") : "Windows Server 2012 R2 Datacenter",
		uuid.UUID("b3ca044e-a358-4d68-9883-aaa2941aca99") : "Windows Server 2012 R2 Standard",
		uuid.UUID("b743a2be-68d4-4dd3-af32-92425b7bb623") : "Windows Server 2012 R2 Cloud Storage",
		uuid.UUID("21db6ba4-9a7b-4a14-9e29-64a60c59301d") : "Windows Server Essentials 2012 R2",
		uuid.UUID("81671aaf-79d1-4eb1-b004-8cbbe173afea") : "Windows 8.1 Enterprise",
		uuid.UUID("113e705c-fa49-48a4-beea-7dd879b46b14") : "Windows 8.1 EnterpriseN",
		uuid.UUID("096ce63d-4fac-48a9-82a9-61ae9e800e5f") : "Windows 8.1 Professional WMC",
		uuid.UUID("c06b6981-d7fd-4a35-b7b4-054742b7af67") : "Windows 8.1 Professional",
		uuid.UUID("7476d79f-8e48-49b4-ab63-4d0b813a16e4") : "Windows 8.1 ProfessionalN",
		uuid.UUID("fe1c3238-432a-43a1-8e25-97e7d1ef10f3") : "Windows 8.1 Core",
		uuid.UUID("78558a64-dc19-43fe-a0d0-8075b2a370a3") : "Windows 8.1 CoreN",
		uuid.UUID("a00018a3-f20f-4632-bf7c-8daa5351c914") : "Windows 8 Professional WMC",
		uuid.UUID("a98bcd6d-5343-4603-8afe-5908e4611112") : "Windows 8 Professional",
		uuid.UUID("ebf245c1-29a8-4daf-9cb1-38dfc608a8c8") : "Windows 8 ProfessionalN",
		uuid.UUID("458e1bec-837a-45f6-b9d5-925ed5d299de") : "Windows 8 Enterprise",
		uuid.UUID("e14997e7-800a-4cf7-ad10-de4b45b578db") : "Windows 8 EnterpriseN",
		uuid.UUID("c04ed6bf-55c8-4b47-9f8e-5a1f31ceee60") : "Windows 8 Core",
		uuid.UUID("197390a0-65f6-4a95-bdc4-55d58a3b0253") : "Windows 8 CoreN",
		uuid.UUID("ae2ee509-1b34-41c0-acb7-6d4650168915") : "Windows 7 Enterprise",
		uuid.UUID("1cb6d605-11b3-4e14-bb30-da91c8e3983a") : "Windows 7 EnterpriseN",
		uuid.UUID("b92e9980-b9d5-4821-9c94-140f632f6312") : "Windows 7 Professional",
		uuid.UUID("54a09a0d-d57b-4c10-8b69-a842d6590ad5") : "Windows 7 ProfessionalN",
		uuid.UUID("cfd8ff08-c0d7-452b-9f60-ef5c70c32094") : "Windows Vista Enterprise",
		uuid.UUID("d4f54950-26f2-4fb4-ba21-ffab16afcade") : "Windows Vista EnterpriseN",
		uuid.UUID("4f3d1606-3fea-4c01-be3c-8d671c401e3b") : "Windows Vista Business",
		uuid.UUID("2c682dc2-8b68-4f63-a165-ae291d4cf138") : "Windows Vista BusinessN",
		uuid.UUID("aa6dd3aa-c2b4-40e2-a544-a6bbb3f5c395") : "Windows ThinPC",
		uuid.UUID("db537896-376f-48ae-a492-53d0547773d0") : "Windows Embedded POSReady 7",
		uuid.UUID("0ab82d54-47f4-4acb-818c-cc5bf0ecb649") : "Windows Embedded Industry 8.1",
		uuid.UUID("cd4e2d9f-5059-4a50-a92d-05d5bb1267c7") : "Windows Embedded IndustryE 8.1",
		uuid.UUID("f7e88590-dfc7-4c78-bccb-6f3865b99d1a") : "Windows Embedded IndustryA 8.1",
		uuid.UUID("8ce7e872-188c-4b98-9d90-f8f90b7aad02") : "Office Access 2010",
		uuid.UUID("cee5d470-6e3b-4fcc-8c2b-d17428568a9f") : "Office Excel 2010",
		uuid.UUID("8947d0b8-c33b-43e1-8c56-9b674c052832") : "Office Groove 2010",
		uuid.UUID("ca6b6639-4ad6-40ae-a575-14dee07f6430") : "Office InfoPath 2010",
		uuid.UUID("09ed9640-f020-400a-acd8-d7d867dfd9c2") : "Office Mondo 2010",
		uuid.UUID("ef3d4e49-a53d-4d81-a2b1-2ca6c2556b2c") : "Office Mondo 2010",
		uuid.UUID("ab586f5c-5256-4632-962f-fefd8b49e6f4") : "Office OneNote 2010",
		uuid.UUID("ecb7c192-73ab-4ded-acf4-2399b095d0cc") : "Office OutLook 2010",
		uuid.UUID("45593b1d-dfb1-4e91-bbfb-2d5d0ce2227a") : "Office PowerPoint 2010",
		uuid.UUID("df133ff7-bf14-4f95-afe3-7b48e7e331ef") : "Office Project Pro 2010",
		uuid.UUID("5dc7bf61-5ec9-4996-9ccb-df806a2d0efe") : "Office Project Standard 2010",
		uuid.UUID("b50c4f75-599b-43e8-8dcd-1081a7967241") : "Office Publisher 2010",
		uuid.UUID("92236105-bb67-494f-94c7-7f7a607929bd") : "Office Visio Premium 2010",
		uuid.UUID("e558389c-83c3-4b29-adfe-5e4d7f46c358") : "Office Visio Pro 2010",
		uuid.UUID("9ed833ff-4f92-4f36-b370-8683a4f13275") : "Office Visio Standard 2010",
		uuid.UUID("2d0882e7-a4e7-423b-8ccc-70d91e0158b1") : "Office Word 2010",
		uuid.UUID("6f327760-8c5c-417c-9b61-836a98287e0c") : "Office Professional Plus 2010",
		uuid.UUID("9da2a678-fb6b-4e67-ab84-60dd6a9c819a") : "Office Standard 2010",
		uuid.UUID("ea509e87-07a1-4a45-9edc-eba5a39f36af") : "Office Small Business Basics 2010",
		uuid.UUID("6ee7622c-18d8-4005-9fb7-92db644a279b") : "Office Access 2013",
		uuid.UUID("f7461d52-7c2b-43b2-8744-ea958e0bd09a") : "Office Excel 2013",
		uuid.UUID("a30b8040-d68a-423f-b0b5-9ce292ea5a8f") : "Office InfoPath 2013",
		uuid.UUID("1b9f11e3-c85c-4e1b-bb29-879ad2c909e3") : "Office Lync 2013",
		uuid.UUID("dc981c6b-fc8e-420f-aa43-f8f33e5c0923") : "Office Mondo 2013",
		uuid.UUID("efe1f3e6-aea2-4144-a208-32aa872b6545") : "Office OneNote 2013",
		uuid.UUID("771c3afa-50c5-443f-b151-ff2546d863a0") : "Office OutLook 2013",
		uuid.UUID("8c762649-97d1-4953-ad27-b7e2c25b972e") : "Office PowerPoint 2013",
		uuid.UUID("4a5d124a-e620-44ba-b6ff-658961b33b9a") : "Office Project Pro 2013",
		uuid.UUID("427a28d1-d17c-4abf-b717-32c780ba6f07") : "Office Project Standard 2013",
		uuid.UUID("00c79ff1-6850-443d-bf61-71cde0de305f") : "Office Publisher 2013",
		uuid.UUID("b13afb38-cd79-4ae5-9f7f-eed058d750ca") : "Office Visio Standard 2013",
		uuid.UUID("e13ac10e-75d0-4aff-a0cd-764982cf541c") : "Office Visio Pro 2013",
		uuid.UUID("d9f5b1c6-5386-495a-88f9-9ad6b41ac9b3") : "Office Word 2013",
		uuid.UUID("b322da9c-a2e2-4058-9e4e-f59a6970bd69") : "Office Professional Plus 2013",
		uuid.UUID("b13afb38-cd79-4ae5-9f7f-eed058d750ca") : "Office Standard 2013",
	}

	licenseStates = {
		0 : "Unlicensed",
		1 : "Activated",
		2 : "Grace Period",
		3 : "Out-of-Tolerance Grace Period",
		4 : "Non-Genuine Grace Period",
		5 : "Notifications Mode",
		6 : "Extended Grace Period",
	}

	licenseStatesEnum = {
		'unlicensed' : 0,
		'licensed' : 1,
		'oobGrace' : 2,
		'ootGrace' : 3,
		'nonGenuineGrace' : 4,
		'notification' : 5,
		'extendedGrace' : 6
	}

	errorCodes = {
		'SL_E_VL_NOT_WINDOWS_SLP' : 0xC004F035,
		'SL_E_VL_NOT_ENOUGH_COUNT' : 0xC004F038,
		'SL_E_VL_BINDING_SERVICE_NOT_ENABLED' : 0xC004F039,
		'SL_E_VL_INFO_PRODUCT_USER_RIGHT' : 0x4004F040,
		'SL_I_VL_OOB_NO_BINDING_SERVER_REGISTRATION' : 0x4004F041,
		'SL_E_VL_KEY_MANAGEMENT_SERVICE_ID_MISMATCH' : 0xC004F042,
		'SL_E_VL_MACHINE_NOT_BOUND' : 0xC004F056
	}

	def __init__(self, data, config):
		self.data = data
		self.config = config

	def getConfig(self):
		return self.config

	def getOptions(self):
		return self.config

	def getData(self):
		return self.data

	def getResponse(self):
		return ''

	def getResponsePadding(self, bodyLength):
		if bodyLength % 8 == 0:
			paddingLength = 0
		else:
			paddingLength = 8 - bodyLength % 8
		padding = bytearray(paddingLength)
		return padding

	def serverLogic(self, kmsRequest):
		if self.config['debug']:
			print "KMS Request Bytes:", binascii.b2a_hex(str(kmsRequest))
			print "KMS Request:", kmsRequest.dump()

		if self.config['verbose']:
			clientMachineId = kmsRequest['clientMachineId'].get()
			applicationId = kmsRequest['applicationId'].get()
			skuId = kmsRequest['skuId'].get()
			requestDatetime = filetimes.filetime_to_dt(kmsRequest['requestTime'])

			# Try and localize the request time, if pytz is available
			try:
				import timezones
				from pytz import utc
				local_dt = utc.localize(requestDatetime).astimezone(timezones.localtz())
			except ImportError:
				local_dt = requestDatetime

			print "     Machine Name: %s" % kmsRequest.getMachineName()
			print "Client Machine ID: %s" % str(clientMachineId)
			print "   Application ID: %s" % self.appIds.get(applicationId, str(applicationId))
			print "           SKU ID: %s" % self.skuIds.get(skuId, str(skuId))
			print "   Licence Status: %s" % kmsRequest.getLicenseStatus()
			print "     Request Time: %s" % local_dt.strftime('%Y-%m-%d %H:%M:%S %Z (UTC%z)')

		return self.createKmsResponse(kmsRequest)

	def createKmsResponse(self, kmsRequest):
		response = self.kmsResponseStruct()
		response['versionMinor'] = kmsRequest['versionMinor']
		response['versionMajor'] = kmsRequest['versionMajor']

		if not self.config["epid"]:
			response["kmsEpid"] = kmsPidGenerator.epidGenerator(kmsRequest['applicationId'], kmsRequest['versionMajor'], self.config["lcid"]).encode('utf-16le')
		else:
			response["kmsEpid"] = self.config["epid"].encode('utf-16le')
		response['clientMachineId'] = kmsRequest['clientMachineId']
		response['responseTime'] = kmsRequest['requestTime']
		response['currentClientCount'] = self.config["CurrentClientCount"]
		response['vLActivationInterval'] = self.config["VLActivationInterval"]
		response['vLRenewalInterval'] = self.config["VLRenewalInterval"]
		if self.config['verbose']:
			print "      Server ePID: %s" % response["kmsEpid"].decode('utf-16le')
		return response

import kmsRequestV4, kmsRequestV5, kmsRequestV6, kmsRequestUnknown

def generateKmsResponseData(data, config):
	version = kmsBase.GenericRequestHeader(data)['versionMajor']
	currentDate = datetime.datetime.now().ctime()

	if version == 4:
		print "Received V%d request on %s." % (version, currentDate)
		messagehandler = kmsRequestV4.kmsRequestV4(data, config)
		messagehandler.executeRequestLogic()
	elif version == 5:
		print "Received V%d request on %s." % (version, currentDate)
		messagehandler = kmsRequestV5.kmsRequestV5(data, config)
		messagehandler.executeRequestLogic()
	elif version == 6:
		print "Received V%d request on %s." % (version, currentDate)
		messagehandler = kmsRequestV6.kmsRequestV6(data, config)
		messagehandler.executeRequestLogic()
	else:
		print "Unhandled KMS version.", version
		messagehandler = kmsRequestUnknown.kmsRequestUnknown(data, config)
	return messagehandler.getResponse()

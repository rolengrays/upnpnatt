
#include <regex>
#include <memory>
#include <Ws2tcpip.h>
#include "upnp_natt.hpp"

namespace upnp_natt
{
	//
	// global var
	//
#pragma region global_var
	namespace
	{
		const std::regex IP_REG(R"(^(([1-9]?[0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([1-9]?[0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$)");
		const std::regex PRIVATE_IP_REG(R"(^192.168.(([1-9]?[0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.)([1-9]?[0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$)");

		const uint32_t ADDRSTRLEN = 16;
		const uint32_t HOSTNAMESTRLEN = 1024;
	}
#pragma endregion global_var

	//
	// global functions
	//
#pragma region global_functions
	namespace
	{
		bool is_equal_bstr(BSTR bstr1, BSTR bstr2)
		{
			uint32_t bstr_len1, bstr_len2;
			uint32_t len;
			bstr_len1 = SysStringLen(bstr1);
			bstr_len2 = SysStringLen(bstr2);

			if (bstr_len1 != bstr_len2)
			{
				return false;
			}
			len = bstr_len1;

			for (uint32_t i = 0; i < len; i++)
			{
				if (bstr1[i] != bstr2[i])
				{
					return false;
				}
			}
			return true;
		}

		void conv_stows(const std::string &src, std::wstring &dst)
		{
			size_t len = src.length();
			size_t ret;
			errno_t e;
			const char *str = src.c_str();
			std::unique_ptr<wchar_t[]> wstr(new wchar_t[len + 1]);

			e = mbstowcs_s(&ret, wstr.get(), len + 1, str, len + 1);

			dst = wstr.get();
		}

		void conv_wstos(const std::wstring &src, std::string &dst)
		{
			size_t len = src.length();
			size_t ret;
			errno_t e;
			std::unique_ptr<char[]> str(new char[len + 1]);
			const wchar_t *wstr = src.c_str();

			e = wcstombs_s(&ret, str.get(), len + 1, wstr, len + 1);

			dst = str.get();
		}

		void conv_bstrtows(const BSTR src, std::wstring &dst)
		{
			uint32_t len = SysStringLen(src);
			std::unique_ptr<wchar_t[]> wstr(new wchar_t[len + 1]);
			for (uint32_t i = 0; i < len; i++)
			{
				wstr[i] = src[i];
			}
			wstr[len] = L'\0';

			dst = wstr.get();
		}

		void conv_bstrtos(const BSTR src, std::string &dst)
		{
			std::wstring wstr;
			conv_bstrtows(src, wstr);
			conv_wstos(wstr, dst);
		}
	}

	bool isPrivateIPAddress(const std::string address)
	{
		std::smatch match;
		return std::regex_match(address, match, PRIVATE_IP_REG);
	}

	std::vector<std::string> getLocalIPAddresses()
	{
		WSADATA wsadata;
		ADDRINFOA *res;
		int error;
		char straddr[ADDRSTRLEN] = {};
		char localhost[HOSTNAMESTRLEN] = {};
		std::vector<std::string> ipAddresses;
		const ADDRINFOA hint = { 0, AF_INET, 0, 0, 0, NULL, NULL, NULL };

		// WSAStartup
		error = WSAStartup(WINSOCK_VERSION, &wsadata);
		if (error != 0)
			return ipAddresses;

		// get local host name
		error = gethostname(localhost, HOSTNAMESTRLEN);
		if (error != 0)
		{
			// cleanup
			WSACleanup();
			return ipAddresses;
		}

		// get local IP address
		error = getaddrinfo(localhost, NULL, &hint, &res);
		while (res != NULL)
		{
			SOCKADDR_IN *sockaddr = (SOCKADDR_IN*)(res->ai_addr);
			inet_ntop(AF_INET, &sockaddr->sin_addr, straddr, sizeof(straddr));
			ipAddresses.push_back(std::string(straddr));
			res = res->ai_next;
		}
		freeaddrinfo(res);

		// cleanup
		WSACleanup();

		return ipAddresses;
	}
#pragma endregion global_functions

#pragma region BSTRManager
	BSTRManager::BSTRManager(BSTR bstr)
	{
		this->bstr = bstr;
	}

	BSTRManager::~BSTRManager()
	{
		if (bstr != NULL)
			SysFreeString(bstr);
	}

	BSTR BSTRManager::get() const
	{
		return bstr;
	}

	BSTR* BSTRManager::getPtr()
	{
		return &bstr;
	}
#pragma endregion BSTRManager

#pragma region VariantManager
	VariantManager::VariantManager()
	{
		VariantInit(&variant);
	}

	VariantManager::~VariantManager()
	{
		VariantClear(&variant);
	}

	VARIANT* VariantManager::getPtr()
	{
		return &variant;
	}
#pragma endregion VariantManager

	//
	// WANConnectionDeviceFinder
	//
#pragma region WANConnectionDeviceFinder
	const wchar_t* WANConnectionDeviceFinder::DEVICE_URN_WAN_CONNECTION_DEVICE = L"urn:schemas-upnp-org:device:WANConnectionDevice:1";
	const wchar_t* WANConnectionDeviceFinder::SERVICE_ID_WAN_PPP_CONNECTION = L"urn:upnp-org:serviceId:WANPPPConn1";
	const wchar_t* WANConnectionDeviceFinder::SERVICE_ID_WAN_IP_CONNECTION = L"urn:upnp-org:serviceId:WANIPConn1";

	WANConnectionDeviceFinder::WANConnectionDeviceFinder() {}

	ErrorCode WANConnectionDeviceFinder::getWANConnectionDevices(std::vector<WANConnectionDevice> &deviceVector)
	{
		HRESULT hr = S_OK;
		try
		{
			// reset vector
			deviceVector.clear();
			deviceVector.shrink_to_fit();

			// CoCreateInstanceEx
			MULTI_QI pResults[1];
			pResults[0].pIID = &IID_IUPnPDeviceFinder;
			pResults[0].pItf = NULL;
			pResults[0].hr = 0;
			hr = CoCreateInstanceEx(
				CLSID_UPnPDeviceFinder,
				NULL,
				CLSCTX_INPROC_SERVER,
				NULL,
				1,
				pResults
			);
			if (hr != S_OK)
			{
				throw UPNPNATT_COM_ERROR;
			}
			hr = pResults[0].hr;
			if (hr != S_OK)
			{
				throw UPNPNATT_COM_ERROR;
			}

			// find devices
			BSTRManager actionName(SysAllocString(DEVICE_URN_WAN_CONNECTION_DEVICE));
			if (actionName.get() == NULL)
			{
				hr = E_OUTOFMEMORY;
				throw UPNPNATT_COM_ERROR;
			}
			IUPnPDeviceFinder *pUPnPDeviceFinder = static_cast<IUPnPDeviceFinder*>(pResults[0].pItf);
			IUPnPDevices *pWANConnectionDevices = NULL;
			hr = pUPnPDeviceFinder->FindByType(actionName.get(), 0, &pWANConnectionDevices);
			pUPnPDeviceFinder->Release();
			if (hr != S_OK)
			{
				throw UPNPNATT_COM_ERROR;
			}

			// get collection object's IUnknown interface
			IUnknown *pUnknown = NULL;
			hr = pWANConnectionDevices->get__NewEnum(&pUnknown);
			pWANConnectionDevices->Release();
			if (hr != S_OK)
			{
				throw UPNPNATT_COM_ERROR;
			}

			// get IEnumVARIANT interface from IUnknown
			IEnumVARIANT *pEnumVarDevice = NULL;
			hr = pUnknown->QueryInterface(IID_IEnumVARIANT, reinterpret_cast<void**>(&pEnumVarDevice));
			pUnknown->Release();
			if (hr != S_OK)
			{
				throw UPNPNATT_COM_ERROR;
			}

			// for each VARIANT Devices...
			VARIANT varCurrentDevice;
			VariantInit(&varCurrentDevice);
			pEnumVarDevice->Reset();
			while (pEnumVarDevice->Next(1, &varCurrentDevice, NULL) == S_OK)
			{
				// get WANConnectionDevice
				IUPnPDevice *pWANConnectionDevice = NULL;
				IDispatch *pDispatchDevice = V_DISPATCH(&varCurrentDevice);
				hr = pDispatchDevice->QueryInterface(IID_IUPnPDevice, reinterpret_cast<void**>(&pWANConnectionDevice));
				pDispatchDevice->Release();
				if (hr != S_OK)
				{
					continue;
				}

				// get WANConnectionService
				IUPnPService *pWANConnectionService = NULL;
				hr = getServiceForNATT(&pWANConnectionDevice, &pWANConnectionService);
				if (hr != S_OK)
				{
					pWANConnectionDevice->Release();
					continue;
				}

				// add device object to vector
				deviceVector.push_back(WANConnectionDevice(pWANConnectionDevice, pWANConnectionService));

				pWANConnectionDevice->Release();
			}
			pEnumVarDevice->Release();

			// check device found
			if (deviceVector.empty())
			{
				throw UPNPNATT_DEVICE_NOT_FOUND;
			}

			return UPNPNATT_OK;
		}
		catch (ErrorCode upnp_natt_error)
		{
			if (upnp_natt_error == UPNPNATT_COM_ERROR)
				setLastCOMError(hr);
			return upnp_natt_error;
		}
	}

	HRESULT WANConnectionDeviceFinder::getLastCOMError() const
	{
		return this->lastCOMError;
	}

	void WANConnectionDeviceFinder::clearLastCOMError()
	{
		this->lastCOMError = S_OK;
	}

	HRESULT WANConnectionDeviceFinder::getServiceForNATT(IUPnPDevice **ppDevice, IUPnPService **ppService)
	{
		HRESULT hr = S_OK;
		try
		{
			// get service collection
			IUPnPServices *pServices = NULL;
			hr = (*ppDevice)->get_Services(&pServices);
			if (hr != S_OK)
			{
				pServices->Release();
				throw hr;
			}

			// alloc BSTR
			BSTRManager WANPPPConnectionId(SysAllocString(SERVICE_ID_WAN_PPP_CONNECTION));
			if (WANPPPConnectionId.get() == NULL)
			{
				pServices->Release();
				throw E_OUTOFMEMORY;
			}
			BSTRManager WANIPConnectionId(SysAllocString(SERVICE_ID_WAN_IP_CONNECTION));
			if (WANIPConnectionId.get() == NULL)
			{
				pServices->Release();
				throw E_OUTOFMEMORY;
			}

			// get service
			IUPnPService *pWANPPPService = NULL;
			IUPnPService *pWANIPService = NULL;
			pServices->get_Item(WANPPPConnectionId.get(), &pWANPPPService);
			pServices->get_Item(WANIPConnectionId.get(), &pWANIPService);

			// get service id
			if (pWANPPPService != NULL)
			{
				*ppService = pWANPPPService;
				if (pWANIPService != NULL)
					pWANIPService->Release();
			}
			else if (pWANIPService != NULL)
			{
				*ppService = pWANIPService;
			}
			else
			{
				pServices->Release();
				throw E_FAIL;
			}

			pServices->Release();
			return S_OK;
		}
		catch (HRESULT hr)
		{
			*ppService = NULL;
			return hr;
		}
	}

	void WANConnectionDeviceFinder::setLastCOMError(HRESULT hr)
	{
		this->lastCOMError = hr;
	}
#pragma endregion WANConnectionDeviceFinder

	//
	// WANConnectionDevice
	//
#pragma region WANConnectionDevice
	const WANConnectionDevice::ActionInfo WANConnectionDevice::addPortMappingAction =
	{
		L"AddPortMapping", 8, 0
	};
	const WANConnectionDevice::ActionInfo WANConnectionDevice::getExternalIPAddressAction =
	{
		L"GetExternalIPAddress", 0, 1
	};
	const WANConnectionDevice::ActionInfo WANConnectionDevice::deletePortMappingAction =
	{
		L"DeletePortMapping", 3, 0
	};
	const WANConnectionDevice::ActionInfo WANConnectionDevice::getSpecificPortMappingEntryAction =
	{
		L"GetSpecificPortMappingEntry", 3, 5
	};

	WANConnectionDevice::WANConnectionDevice()
	{
		this->pWANConnectionDevice = NULL;
		this->pWANConnectionService = NULL;
	}

	WANConnectionDevice::WANConnectionDevice(IUPnPDevice * pWANConnectionDevice, IUPnPService * pWANConnectionService)
	{
		this->pWANConnectionDevice = pWANConnectionDevice;
		this->pWANConnectionService = pWANConnectionService;
		this->pWANConnectionDevice->AddRef();
		this->pWANConnectionService->AddRef();
	}

	WANConnectionDevice::~WANConnectionDevice()
	{
		if (pWANConnectionDevice != NULL)
			pWANConnectionDevice->Release();

		if (pWANConnectionService != NULL)
			pWANConnectionService->Release();
	}

	WANConnectionDevice::WANConnectionDevice(const WANConnectionDevice & src)
	{
		if (src.pWANConnectionDevice != NULL)
			src.pWANConnectionDevice->AddRef();

		if (src.pWANConnectionService != NULL)
			src.pWANConnectionService->AddRef();

		this->pWANConnectionDevice = src.pWANConnectionDevice;
		this->pWANConnectionService = src.pWANConnectionService;
	}

	WANConnectionDevice & upnp_natt::WANConnectionDevice::operator=(const WANConnectionDevice & src)
	{

		if (!(this->pWANConnectionDevice == src.pWANConnectionDevice))
		{
			if (src.pWANConnectionDevice != NULL)
				src.pWANConnectionDevice->AddRef();

			if (this->pWANConnectionDevice != NULL)
				this->pWANConnectionDevice->Release();

			this->pWANConnectionDevice = src.pWANConnectionDevice;
		}

		if (!(this->pWANConnectionService == src.pWANConnectionService))
		{
			if (src.pWANConnectionService != NULL)
				src.pWANConnectionService->AddRef();

			if (this->pWANConnectionService != NULL)
				this->pWANConnectionService->Release();

			this->pWANConnectionService = src.pWANConnectionService;
		}

		return *this;
	}

	ErrorCode WANConnectionDevice::getRootDeviceFriendlyName(std::string & friendlyName)
	{
		// get model name
		HRESULT hr = S_OK;
		try
		{
			// check device object
			if (pWANConnectionDevice == NULL || pWANConnectionService == NULL)
			{
				throw UPNPNATT_INVALID_DEVICE_OBJECT;
			}

			BSTRManager friendlyNameBSTR(NULL);
			IUPnPDevice *pRootDevice = NULL;		

			hr = pWANConnectionDevice->get_RootDevice(&pRootDevice);
			if (hr != S_OK)
			{
				throw UPNPNATT_COM_ERROR;
			}
			hr = pRootDevice->get_FriendlyName((friendlyNameBSTR.getPtr()));
			if (hr != S_OK)
			{
				pRootDevice->Release();
				throw UPNPNATT_COM_ERROR;
			}
			conv_bstrtos(friendlyNameBSTR.get(), friendlyName);

			pRootDevice->Release();
			return UPNPNATT_OK;
		}
		catch (ErrorCode upnp_natt_error)
		{
			if (upnp_natt_error == UPNPNATT_COM_ERROR)
				setLastCOMError(hr);
			return upnp_natt_error;
		}
	}

	ErrorCode WANConnectionDevice::getExternalIPAddress(std::string & ipAddress)
	{
		ErrorCode upnp_natt_error = UPNPNATT_OK;
		HRESULT hr = S_OK;
		try
		{
			// check device object
			if (pWANConnectionDevice == NULL || pWANConnectionService == NULL)
			{
				throw UPNPNATT_INVALID_DEVICE_OBJECT;
			}

			// create arg array
			SAFEARRAY *pSafeArgArray = NULL;
			SAFEARRAYBOUND rgsaBound[1];
			rgsaBound[0].lLbound = 0;
			rgsaBound[0].cElements = 1;
			pSafeArgArray = SafeArrayCreate(VT_VARIANT, 1, rgsaBound);
			if (pSafeArgArray == NULL)
			{
				hr = E_OUTOFMEMORY;
				throw UPNPNATT_COM_ERROR;
			}

			// Invoke action
			VariantManager inArgs;
			VariantManager outArgs;
			VariantManager result;
			hr = invokeAction(&pWANConnectionService, getExternalIPAddressAction.name, &pSafeArgArray, inArgs.getPtr(), outArgs.getPtr(), result.getPtr());
			if (hr != S_OK)
			{
				ErrorCode new_upnp_natt_error = UPNPNATT_OK;
				HRESULT newhr = S_OK;
				convInvokeActionErrorInfo(hr, new_upnp_natt_error, newhr);
				hr = newhr;
				throw new_upnp_natt_error;
			}

			// get ip address
			VariantManager varIPAddr;
			long idx = 0;
			hr = SafeArrayGetElement(V_ARRAY(outArgs.getPtr()), &idx, static_cast<void*>(varIPAddr.getPtr()));
			if (hr != S_OK)
			{
				throw UPNPNATT_COM_ERROR;
			}
			conv_bstrtos(V_BSTR(varIPAddr.getPtr()), ipAddress);

			return UPNPNATT_OK;
		}
		catch (ErrorCode upnp_natt_error)
		{
			ipAddress = "";
			if (upnp_natt_error == UPNPNATT_COM_ERROR)
				setLastCOMError(hr);
			if (upnp_natt_error == UPNPNATT_UPNP_DEVICE_ERROR)
				setLastUPnPDeviceError(hr);
			return upnp_natt_error;
		}
	}

	ErrorCode WANConnectionDevice::addPortMapping(const PortMappingInfo &portMappingInfo)
	{
		ErrorCode upnp_natt_error = UPNPNATT_OK;
		HRESULT hr = S_OK;
		try
		{
			// check device object
			if (pWANConnectionDevice == NULL || pWANConnectionService == NULL)
			{
				throw UPNPNATT_INVALID_DEVICE_OBJECT;
			}

			// check port mapping protocol
			if ((portMappingInfo.protocol != UDP_PORTMAP) && (portMappingInfo.protocol != TCP_PORTMAP))
			{
				throw UPNPNATT_INVALID_PROTOCOL;
			}

			// check remote host
			std::smatch matchrh;
			if (!portMappingInfo.remoteHost.empty() && !std::regex_match(portMappingInfo.remoteHost, matchrh, IP_REG))
			{
				throw UPNPNATT_INVALID_REMOTE_HOST;
			}

			// check internal client
			std::smatch matchic;
			if (!std::regex_match(portMappingInfo.internalClient, matchic, IP_REG))
			{
				throw UPNPNATT_INVALID_INTERNAL_CLIENT;
			}

			// create arg array
			SAFEARRAY *pSafeArgArray = NULL;
			SAFEARRAYBOUND rgsaBound[1];
			rgsaBound[0].lLbound = 0;
			rgsaBound[0].cElements = addPortMappingAction.numInArgs;
			pSafeArgArray = SafeArrayCreate(VT_VARIANT, 1, rgsaBound);
			if (pSafeArgArray == NULL)
			{
				hr = E_OUTOFMEMORY;
				throw UPNPNATT_COM_ERROR;
			}

			// set args
			VarPortMappingInfo varPortMappingInfo;
			hr = varPortMappingInfo.initialize(portMappingInfo);
			if (hr != S_OK)
			{
				SafeArrayDestroy(pSafeArgArray);
				throw UPNPNATT_COM_ERROR;
			}

			// put args in array
			std::unique_ptr<long[]> inIds(new long[addPortMappingAction.numInArgs]);
			for (int i = 0; i < addPortMappingAction.numInArgs; i++)
			{
				inIds[i] = i;
			}
			SafeArrayPutElement(pSafeArgArray, &inIds[0], static_cast<void*>(varPortMappingInfo.varRemoteHost.getPtr()));
			SafeArrayPutElement(pSafeArgArray, &inIds[1], static_cast<void*>(varPortMappingInfo.varExternalPort.getPtr()));
			SafeArrayPutElement(pSafeArgArray, &inIds[2], static_cast<void*>(varPortMappingInfo.varProtocol.getPtr()));
			SafeArrayPutElement(pSafeArgArray, &inIds[3], static_cast<void*>(varPortMappingInfo.varInternalPort.getPtr()));
			SafeArrayPutElement(pSafeArgArray, &inIds[4], static_cast<void*>(varPortMappingInfo.varInternalClient.getPtr()));
			SafeArrayPutElement(pSafeArgArray, &inIds[5], static_cast<void*>(varPortMappingInfo.varEnabled.getPtr()));
			SafeArrayPutElement(pSafeArgArray, &inIds[6], static_cast<void*>(varPortMappingInfo.varDescription.getPtr()));
			SafeArrayPutElement(pSafeArgArray, &inIds[7], static_cast<void*>(varPortMappingInfo.varLeaseduration.getPtr()));

			// Invoke action
			VariantManager inArgs;
			VariantManager outArgs;
			VariantManager result;
			hr = invokeAction(&pWANConnectionService, addPortMappingAction.name, &pSafeArgArray, inArgs.getPtr(), outArgs.getPtr(), result.getPtr());
			if (hr != S_OK)
			{
				ErrorCode new_upnp_natt_error = UPNPNATT_OK;
				HRESULT newhr = S_OK;
				convInvokeActionErrorInfo(hr, new_upnp_natt_error, newhr);
				hr = newhr;
				throw new_upnp_natt_error;
			}

			return UPNPNATT_OK;
		}
		catch (ErrorCode upnp_natt_error)
		{
			if (upnp_natt_error == UPNPNATT_COM_ERROR)
				setLastCOMError(hr);

			if (upnp_natt_error == UPNPNATT_UPNP_DEVICE_ERROR)
				setLastUPnPDeviceError(hr);
			return upnp_natt_error;
		}
	}

	ErrorCode WANConnectionDevice::deletePortMapping(const PortMappingInfo &portMappingInfo)
	{
		ErrorCode upnp_natt_error = UPNPNATT_OK;
		HRESULT hr = S_OK;
		try
		{
			// check device object
			if (pWANConnectionDevice == NULL || pWANConnectionService == NULL)
			{
				throw UPNPNATT_INVALID_DEVICE_OBJECT;
			}

			// check port mapping protocol
			if ((portMappingInfo.protocol != UDP_PORTMAP) && (portMappingInfo.protocol != TCP_PORTMAP))
			{
				throw UPNPNATT_INVALID_PROTOCOL;
			}

			// check remote host
			std::smatch matchrh;
			if (!portMappingInfo.remoteHost.empty() && !std::regex_match(portMappingInfo.remoteHost, matchrh, IP_REG))
			{
				throw UPNPNATT_INVALID_REMOTE_HOST;
			}

			// create arg array
			SAFEARRAY *pSafeArgArray = NULL;
			SAFEARRAYBOUND rgsaBound[1];
			rgsaBound[0].lLbound = 0;
			rgsaBound[0].cElements = deletePortMappingAction.numInArgs;
			pSafeArgArray = SafeArrayCreate(VT_VARIANT, 1, rgsaBound);
			if (pSafeArgArray == NULL)
			{
				hr = E_OUTOFMEMORY;
				throw UPNPNATT_COM_ERROR;
			}

			// set args
			VarPortMappingInfo varPortMappingInfo;
			hr = varPortMappingInfo.initialize(portMappingInfo);
			if (hr != S_OK)
			{
				SafeArrayDestroy(pSafeArgArray);
				throw UPNPNATT_COM_ERROR;
			}

			// put args in array
			std::unique_ptr<long[]> inIds(new long[deletePortMappingAction.numInArgs]);
			for (int i = 0; i < deletePortMappingAction.numInArgs; i++)
			{
				inIds[i] = i;
			}
			SafeArrayPutElement(pSafeArgArray, &inIds[0], static_cast<void*>(varPortMappingInfo.varRemoteHost.getPtr()));
			SafeArrayPutElement(pSafeArgArray, &inIds[1], static_cast<void*>(varPortMappingInfo.varExternalPort.getPtr()));
			SafeArrayPutElement(pSafeArgArray, &inIds[2], static_cast<void*>(varPortMappingInfo.varProtocol.getPtr()));

			// Invoke action
			VariantManager inArgs;
			VariantManager outArgs;
			VariantManager result;
			hr = invokeAction(&pWANConnectionService, deletePortMappingAction.name, &pSafeArgArray, inArgs.getPtr(), outArgs.getPtr(), result.getPtr());
			if (hr != S_OK)
			{
				ErrorCode new_upnp_natt_error = UPNPNATT_OK;
				HRESULT newhr = S_OK;
				convInvokeActionErrorInfo(hr, new_upnp_natt_error, newhr);
				hr = newhr;
				throw new_upnp_natt_error;
			}

			return UPNPNATT_OK;
		}
		catch (ErrorCode upnp_natt_error)
		{
			if (upnp_natt_error == UPNPNATT_COM_ERROR)
				setLastCOMError(hr);

			if (upnp_natt_error == UPNPNATT_UPNP_DEVICE_ERROR)
				setLastUPnPDeviceError(hr);

			return upnp_natt_error;
		}
	}

	ErrorCode WANConnectionDevice::getSpecificPortMappingEntry(const PortMappingInfo & hint, PortMappingInfo & portMappingInfo)
	{
		ErrorCode upnp_natt_error = UPNPNATT_OK;
		HRESULT hr = S_OK;

		portMappingInfo.remoteHost = "";
		portMappingInfo.externalPort = 0;
		portMappingInfo.protocol = NO_PROTOCOL_SETTING;
		portMappingInfo.enabled = false;
		portMappingInfo.internalPort = 0;
		portMappingInfo.internalClient = "";
		portMappingInfo.leaseDuration = 0;
		portMappingInfo.portMappingDescription = "";

		try
		{
			// check device object
			if (pWANConnectionDevice == NULL || pWANConnectionService == NULL)
			{
				throw UPNPNATT_INVALID_DEVICE_OBJECT;
			}

			// check port mapping protocol
			if ((hint.protocol != UDP_PORTMAP) && (hint.protocol != TCP_PORTMAP))
			{
				throw UPNPNATT_INVALID_PROTOCOL;
			}

			// check remote host
			std::smatch matchrh;
			if (!hint.remoteHost.empty() && !std::regex_match(hint.remoteHost, matchrh, IP_REG))
			{
				throw UPNPNATT_INVALID_REMOTE_HOST;
			}

			// create arg array
			SAFEARRAY *pSafeArgArray = NULL;
			SAFEARRAYBOUND rgsaBound[1];
			rgsaBound[0].lLbound = 0;
			rgsaBound[0].cElements = getSpecificPortMappingEntryAction.numInArgs;
			pSafeArgArray = SafeArrayCreate(VT_VARIANT, 1, rgsaBound);
			if (pSafeArgArray == NULL)
			{
				hr = E_OUTOFMEMORY;
				throw UPNPNATT_COM_ERROR;
			}

			// set args
			VarPortMappingInfo varPortMappingInfo;
			hr = varPortMappingInfo.initialize(hint);
			if (hr != S_OK)
			{
				SafeArrayDestroy(pSafeArgArray);
				throw UPNPNATT_COM_ERROR;
			}

			// put args in array
			std::unique_ptr<long[]> inIds(new long[getSpecificPortMappingEntryAction.numInArgs]);
			for (int i = 0; i < getSpecificPortMappingEntryAction.numInArgs; i++)
			{
				inIds[i] = i;
			}
			SafeArrayPutElement(pSafeArgArray, &inIds[0], static_cast<void*>(varPortMappingInfo.varRemoteHost.getPtr()));
			SafeArrayPutElement(pSafeArgArray, &inIds[1], static_cast<void*>(varPortMappingInfo.varExternalPort.getPtr()));
			SafeArrayPutElement(pSafeArgArray, &inIds[2], static_cast<void*>(varPortMappingInfo.varProtocol.getPtr()));

			// invoke action
			VariantManager inArgs;
			VariantManager outArgs;
			VariantManager result;
			hr = invokeAction(&pWANConnectionService, getSpecificPortMappingEntryAction.name, &pSafeArgArray, inArgs.getPtr(), outArgs.getPtr(), result.getPtr());
			if (hr != S_OK)
			{
				ErrorCode new_upnp_natt_error = UPNPNATT_OK;
				HRESULT newhr = S_OK;
				convInvokeActionErrorInfo(hr, new_upnp_natt_error, newhr);
				hr = newhr;
				throw new_upnp_natt_error;
			}

			// get out args
			VarPortMappingInfo outVarPortMappingInfo;
			hr = outVarPortMappingInfo.initialize(hint);
			if (hr != S_OK)
			{
				throw UPNPNATT_COM_ERROR;
			}
			std::unique_ptr<long[]> outIds(new long[getSpecificPortMappingEntryAction.numOutArgs]);
			for (int i = 0; i < getSpecificPortMappingEntryAction.numOutArgs; i++)
			{
				outIds[i] = i;
			}
			SafeArrayGetElement(V_ARRAY(outArgs.getPtr()), &outIds[0], static_cast<void*>(outVarPortMappingInfo.varInternalPort.getPtr()));
			SafeArrayGetElement(V_ARRAY(outArgs.getPtr()), &outIds[1], static_cast<void*>(outVarPortMappingInfo.varInternalClient.getPtr()));
			SafeArrayGetElement(V_ARRAY(outArgs.getPtr()), &outIds[2], static_cast<void*>(outVarPortMappingInfo.varEnabled.getPtr()));
			SafeArrayGetElement(V_ARRAY(outArgs.getPtr()), &outIds[3], static_cast<void*>(outVarPortMappingInfo.varDescription.getPtr()));
			SafeArrayGetElement(V_ARRAY(outArgs.getPtr()), &outIds[4], static_cast<void*>(outVarPortMappingInfo.varLeaseduration.getPtr()));

			// set out args
			std::string strInternalClient;
			std::string strDescription;
			conv_bstrtos(V_BSTR(outVarPortMappingInfo.varInternalClient.getPtr()), strInternalClient);
			conv_bstrtos(V_BSTR(outVarPortMappingInfo.varDescription.getPtr()), strDescription);

			portMappingInfo.remoteHost = hint.remoteHost;
			portMappingInfo.externalPort = hint.externalPort;
			portMappingInfo.protocol = hint.protocol;
			portMappingInfo.internalPort = V_UI2(outVarPortMappingInfo.varInternalPort.getPtr());
			portMappingInfo.internalClient = strInternalClient;
			portMappingInfo.enabled = (V_BOOL(outVarPortMappingInfo.varEnabled.getPtr()) == -1);
			portMappingInfo.portMappingDescription = strDescription;
			portMappingInfo.leaseDuration = V_UI2(outVarPortMappingInfo.varLeaseduration.getPtr());

			return UPNPNATT_OK;
		}
		catch (ErrorCode upnp_natt_error)
		{
			if (upnp_natt_error == UPNPNATT_COM_ERROR)
				setLastCOMError(hr);
			if (upnp_natt_error == UPNPNATT_UPNP_DEVICE_ERROR)
				setLastUPnPDeviceError(hr);
			return upnp_natt_error;
		}
	}

	HRESULT WANConnectionDevice::getLastCOMError() const
	{
		return this->lastCOMError;
	}

	void WANConnectionDevice::clearLastCOMError()
	{
		this->lastCOMError = S_OK;
	}

	UPnPDeviceErrorCode WANConnectionDevice::getLastUPnPDeviceError() const
	{
		return this->lastUPnPDeviceError;
	}

	void WANConnectionDevice::clearLastUPnPDeviceError()
	{
		this->lastUPnPDeviceError = DEVICE_OK;
	}

	HRESULT WANConnectionDevice::invokeAction(IUPnPService **ppService, const wchar_t* name, SAFEARRAY **ppSafeInArgArray, VARIANT *inArgs, VARIANT *outArgs, VARIANT *result)
	{
		HRESULT hr = S_OK;
		ErrorCode upnp_natt_error = UPNPNATT_OK;
		BSTRManager actionName(SysAllocString(name));
		if (actionName.get() == NULL)
		{
			throw E_OUTOFMEMORY;
		}

		inArgs->vt = VT_ARRAY | VT_VARIANT;
		V_ARRAY(inArgs) = *ppSafeInArgArray;
		hr = (*ppService)->InvokeAction(actionName.get(), *inArgs, outArgs, result);

		return hr;
	}

	void  WANConnectionDevice::convInvokeActionErrorInfo(HRESULT hr, ErrorCode &errorcode, HRESULT& newhr)
	{
		InvokeActionErrorType errortype;
		if ((UPNP_E_ACTION_SPECIFIC_BASE <= hr) && (hr <= UPNP_E_ACTION_SPECIFIC_MAX))
		{
			newhr = (hr - UPNP_E_ACTION_SPECIFIC_BASE) + FAULT_ACTION_SPECIFIC_BASE;
			errortype = ERROR_TYPE_UPNPDEVICE;
		}
		else if (hr < UPNP_E_ACTION_SPECIFIC_BASE)
		{
			switch (hr)
			{
			case UPNP_E_INVALID_ACTION:
				newhr = FAULT_INVALID_ACTION;
				break;
			case UPNP_E_INVALID_ARGUMENTS:
				newhr = FAULT_INVALID_ARG;
				break;
			case UPNP_E_OUT_OF_SYNC:
				newhr = FAULT_INVALID_SEQUENCE_NUMBER;
				break;
			case UPNP_E_INVALID_VARIABLE:
				newhr = FAULT_INVALID_VARIABLE;
				break;
			case UPNP_E_ACTION_REQUEST_FAILED:
				newhr = FAULT_DEVICE_INTERNAL_ERROR;
				break;
			}
			errortype = ERROR_TYPE_UPNPDEVICE;
		}
		else
		{
			switch (hr)
			{
			case UPNP_E_DEVICE_ERROR:
				newhr = 301L;
				errortype = ERROR_TYPE_UPNPDEVICE;
				break;
			case UPNP_E_DEVICE_TIMEOUT:
				newhr = 302L;
				errortype = ERROR_TYPE_UPNPDEVICE;
				break;
			case UPNP_E_PROTOCOL_ERROR:
				newhr = 303L;
				errortype = ERROR_TYPE_UPNPDEVICE;
				break;
			case UPNP_E_TRANSPORT_ERROR:
				newhr = 304L;
				errortype = ERROR_TYPE_UPNPDEVICE;
				break;
			default:
				newhr = hr;
				errortype = ERROR_TYPE_COM;
				break;
			}
		}

		switch (errortype)
		{
		case ERROR_TYPE_COM:
			errorcode = UPNPNATT_COM_ERROR;
			break;
		case ERROR_TYPE_UPNPDEVICE:
			errorcode = UPNPNATT_UPNP_DEVICE_ERROR;
			break;
		default:
			errorcode = UPNPNATT_UNKNOWN_ERROR;
			break;
		}
	}

	void WANConnectionDevice::setLastCOMError(HRESULT hr)
	{
		this->lastCOMError = hr;
	}

	void WANConnectionDevice::setLastUPnPDeviceError(HRESULT hr)
	{
		this->lastUPnPDeviceError = static_cast<UPnPDeviceErrorCode>(hr);
	}

	WANConnectionDevice::VarPortMappingInfo::VarPortMappingInfo()
	{
		varRemoteHost.getPtr()->vt = VT_BSTR;
		varExternalPort.getPtr()->vt = VT_UI2;
		varProtocol.getPtr()->vt = VT_BSTR;
		varInternalPort.getPtr()->vt = VT_UI2;
		varInternalClient.getPtr()->vt = VT_BSTR;
		varEnabled.getPtr()->vt = VT_BOOL;
		varDescription.getPtr()->vt = VT_BSTR;
		varLeaseduration.getPtr()->vt = VT_UI4;

		initialized = false;
	}

	HRESULT WANConnectionDevice::VarPortMappingInfo::initialize(PortMappingInfo portMappingInfo)
	{
		if (initialized)
			return E_FAIL;

		std::wstring wRemoteHost;
		std::wstring wProtocol;
		std::wstring wInternalClient;
		std::wstring wDescription;

		switch (portMappingInfo.protocol)
		{
		case UDP_PORTMAP:
			wProtocol = L"UDP";
		case TCP_PORTMAP:
			wProtocol = L"TCP";
		}

		conv_stows(portMappingInfo.remoteHost, wRemoteHost);
		conv_stows(portMappingInfo.internalClient, wInternalClient);
		conv_stows(portMappingInfo.portMappingDescription, wDescription);

		V_BSTR(varRemoteHost.getPtr()) = SysAllocString(wRemoteHost.c_str());
		V_UI2(varExternalPort.getPtr()) = portMappingInfo.externalPort;
		V_BSTR(varProtocol.getPtr()) = SysAllocString(wProtocol.c_str());
		V_UI2(varInternalPort.getPtr()) = portMappingInfo.internalPort;
		V_BSTR(varInternalClient.getPtr()) = SysAllocString(wInternalClient.c_str());
		V_BOOL(varEnabled.getPtr()) = (portMappingInfo.enabled) ? -1 : 0;
		V_BSTR(varDescription.getPtr()) = SysAllocString(wDescription.c_str());
		V_UI4(varLeaseduration.getPtr()) = portMappingInfo.leaseDuration;

		if ((V_BSTR(varRemoteHost.getPtr()) == NULL) |
			(V_BSTR(varProtocol.getPtr()) == NULL) |
			(V_BSTR(varInternalClient.getPtr()) == NULL) |
			(V_BSTR(varDescription.getPtr()) == NULL))
		{
			reset();
			return E_OUTOFMEMORY;
		}

		initialized = true;
		return S_OK;
	}

	void WANConnectionDevice::VarPortMappingInfo::reset()
	{
		V_UI2(varExternalPort.getPtr()) = 0;
		V_UI2(varInternalPort.getPtr()) = 0;
		V_BOOL(varEnabled.getPtr()) = 0;
		V_UI4(varLeaseduration.getPtr()) = 0;

		if (V_BSTR(varRemoteHost.getPtr()) == NULL)
		{
			SysFreeString(V_BSTR(varRemoteHost.getPtr()));
		}
		if (V_BSTR(varProtocol.getPtr()) == NULL)
		{
			SysFreeString(V_BSTR(varProtocol.getPtr()));
		}
		if (V_BSTR(varInternalClient.getPtr()) == NULL)
		{
			SysFreeString(V_BSTR(varInternalClient.getPtr()));
		}
		if (V_BSTR(varDescription.getPtr()) == NULL)
		{
			SysFreeString(V_BSTR(varDescription.getPtr()));
		}

		initialized = false;
	}
#pragma endregion WANConnectionDevice
} // upnp_natt ns
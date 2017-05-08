
#ifndef MY_UPNP_NATT_H_
#define MY_UPNP_NATT_H_

#include<string>
#include<vector>
#include<stdint.h>
#include<UPnP.h>

namespace upnp_natt
{
	//
	// Overview:
	//	Error cord of UPNP NAT-T
	typedef enum tagErrorCode
	{
		UPNPNATT_OK,
		UPNPNATT_INVALID_PROTOCOL,
		UPNPNATT_INVALID_REMOTE_HOST,
		UPNPNATT_INVALID_INTERNAL_CLIENT,
		UPNPNATT_INVALID_DEVICE_OBJECT,
		UPNPNATT_DEVICE_NOT_FOUND,
		UPNPNATT_COM_ERROR,
		UPNPNATT_UPNP_DEVICE_ERROR,
		UPNPNATT_UNKNOWN_ERROR
	} ErrorCode;

	//
	// Overview:
	//	Error code of UPnP Device error
	typedef enum tagUPnPDeviceErrorCode
	{
		DEVICE_OK = 0,
		UNKNOWN_ERROR = 301,
		DEVICE_TIMEOUT = 302,
		PROTOCOL_ERROR = 303,
		HTTP_ERROR = 304,
		INVALID_ACTION = 401,
		INVALID_ARGS = 402,
		INVALID_VAR = 404,
		ACTION_FAILED = 501,
		NO_SUCH_ENTRY_IN_ARRAY = 714,
		WILD_CARD_NOT_PERMITTED_IN_SRC_IP = 715,
		WILD_CARD_NOT_PERMITTED_IN_EXT_PORT = 716,
		CONFLICT_IN_MAPPING_ENTRY = 718,
		SAME_PORT_VALUES_REQUIRED = 724,
		ONLY_PERMANENT_LEASES_SUPPORTED = 725,
		REMOTE_HOST_ONLY_SUPPORTS_WILDCARD = 726,
		EXTERNAL_PORT_ONLY_SUPPORTS_WILDCARD = 727
	} UPnPDeviceErrorCode;

	//
	// Overview:
	//	Protocol which is used for port mapping
	typedef enum tagPortMappingProtocol
	{
		NO_PROTOCOL_SETTING,
		UDP_PORTMAP,
		TCP_PORTMAP
	} PortMappingProtocol;

	//
	// Overview:
	//	Parameters for port mapping
	typedef struct tagPortMappingInfo
	{
		std::string remoteHost;
		uint16_t externalPort;
		PortMappingProtocol protocol;
		uint16_t internalPort;
		std::string internalClient;
		bool enabled;
		std::string portMappingDescription;
		uint16_t leaseDuration;
	} PortMappingInfo;

	//
	// Overview:
	//  Get IPv4 Addresses of local machine.
	std::vector<std::string> getLocalIPAddresses();

	//
	// Overviwe:
	//	Returns true if specified IP address is private IP Address.
	bool isPrivateIPAddress(const std::string address);

	//
	// Overview:
	//  Wrapper class of BSTR
	class BSTRManager
	{
	private:
		BSTR bstr;

		// unenble default constructor
		BSTRManager();

		// copy guard
		BSTRManager(const BSTRManager &src);
		BSTRManager& operator=(const BSTRManager &src);

	public:
		BSTRManager(BSTR bstr);
		~BSTRManager();
		BSTR get() const;
		BSTR* getPtr();
	};

	//
	// Overview:
	//	Wrapper class of VARIANT
	class VariantManager
	{
	private:
		VARIANT variant;

		// copy guard
		VariantManager(const VariantManager &src);
		VariantManager& operator=(const VariantManager &src);
	public:
		VariantManager();
		~VariantManager();
		VARIANT* getPtr();
	};

	//
	// Overview:
	//  Routing device that supports UPnP.
	class WANConnectionDevice
	{
	private:
		class VarPortMappingInfo
		{
		private:
			// copy guard
			VarPortMappingInfo(const VarPortMappingInfo &src);
			VarPortMappingInfo& operator= (const VarPortMappingInfo &src);

			bool initialized;

		public:
			VariantManager varRemoteHost;
			VariantManager varExternalPort;
			VariantManager varProtocol;
			VariantManager varInternalPort;
			VariantManager varInternalClient;
			VariantManager varEnabled;
			VariantManager varDescription;
			VariantManager varLeaseduration;

			VarPortMappingInfo();
			HRESULT initialize(PortMappingInfo portMappingInfo);
			void reset();
		};

		typedef struct tagActionInfo
		{
			const wchar_t *name;
			const uint16_t numInArgs;
			const uint16_t numOutArgs;
		}ActionInfo;

		typedef enum tagInvokeActionErrorType
		{
			ERROR_TYPE_COM,
			ERROR_TYPE_UPNPDEVICE
		} InvokeActionErrorType;

		static const ActionInfo addPortMappingAction;
		static const ActionInfo getExternalIPAddressAction;
		static const ActionInfo deletePortMappingAction;
		static const ActionInfo getSpecificPortMappingEntryAction;

		IUPnPDevice *pWANConnectionDevice;
		IUPnPService *pWANConnectionService;
		HRESULT lastCOMError;
		UPnPDeviceErrorCode lastUPnPDeviceError;

		HRESULT invokeAction(IUPnPService **ppService, const wchar_t* name, SAFEARRAY **ppSafeInArgArray, VARIANT *inArgs, VARIANT *outArgs, VARIANT *result);
		void convInvokeActionErrorInfo(HRESULT hr, ErrorCode& errorcode, HRESULT& newhr);
		void setLastCOMError(HRESULT hr);
		void setLastUPnPDeviceError(HRESULT hr);

	public:
		WANConnectionDevice();
		WANConnectionDevice(IUPnPDevice *pWANConnectionDevice, IUPnPService * pWANConnectionService);
		virtual ~WANConnectionDevice();
		WANConnectionDevice(const WANConnectionDevice& obj);
		WANConnectionDevice& operator= (const WANConnectionDevice &src);

		//
		// Overview:
		//	Get this device model name.
		ErrorCode getRootDeviceFriendlyName(std::string &friendlyName);

		//
		// Overview:
		//  Get External IP Address of this router.
		ErrorCode getExternalIPAddress(std::string &ipAddress);

		//
		// Overview:
		//  Add port mapping to this router.
		ErrorCode addPortMapping(const PortMappingInfo &portMappingInfo);

		//
		// Overview:
		//  Delete port mapping from this router.
		ErrorCode deletePortMapping(const PortMappingInfo &portMappingInfo);

		//
		// Overview:
		//	Get current port mapping information about specified host, port, protocol.
		ErrorCode getSpecificPortMappingEntry(const PortMappingInfo &hint, PortMappingInfo &portMappingInfo);

		//
		// Overview:
		//  Get last COM error code.
		HRESULT getLastCOMError() const;

		//
		// Overview:
		//  Clear last COM error code.
		void clearLastCOMError();

		//
		// Overview:
		//  Get last UPnP device error code.
		UPnPDeviceErrorCode getLastUPnPDeviceError() const;

		//
		// Overview:
		//  Clear last UPnP device error code. 
		void clearLastUPnPDeviceError();
	};

	//
	// Overview:
	//  WANConnection object finder.
	class WANConnectionDeviceFinder
	{
	private:
		HRESULT getServiceForNATT(IUPnPDevice **ppDevice, IUPnPService **ppService);
		HRESULT lastCOMError;
		void setLastCOMError(HRESULT hr);
		static const wchar_t* DEVICE_URN_WAN_CONNECTION_DEVICE;
		static const wchar_t* SERVICE_ID_WAN_PPP_CONNECTION;
		static const wchar_t* SERVICE_ID_WAN_IP_CONNECTION;

	public:
		WANConnectionDeviceFinder();

		//
		// Overview: 
		//	Find and get vector of WANConnectionDevice object.
		ErrorCode getWANConnectionDevices(std::vector<WANConnectionDevice> &deviceVector);

		//
		// Overview:
		//  Get last COM error cord.
		HRESULT getLastCOMError() const;

		//
		// Overview:
		//  Clear last COM error cord.
		void clearLastCOMError();
	};
} // upnp_natt ns

#endif
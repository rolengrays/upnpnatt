
#include<iostream>
#include"upnp_natt.hpp"

const char* UPNP_NATT_ERROR_MESSAGES[] =
{
	"No Errors",					// UPNPNATT_OK
	"Invalid protocol",				// UPNPNATT_INVALID_PROTOCOL
	"Invalid remote host",			// UPNPNATT_INVALID_REMOTE_HOST
	"Invalid internal client",		// UPNPNATT_INVALID_INTERNAL_CLIENT
	"Invalid device object",		// UPNPNATT_INVALID_DEVICE_OBJECT
	"No devices found",				// UPNPNATT_DEVICE_NOT_FOUND
	"COM error",					// UPNPNATT_COM_ERROR
	"UPnP device error",			// UPNPNATT_UPNP_DEVICE_ERROR
	"Unknown Error"					// UPNPNATT_UNKNOWN_ERROR
};

int main(char argc, char* argv[])
{
	upnp_natt::WANConnectionDeviceFinder deviceFinder;
	std::vector<upnp_natt::WANConnectionDevice> devices;
	upnp_natt::WANConnectionDevice firstdevice;
	upnp_natt::PortMappingInfo port_mapping_info;
	upnp_natt::ErrorCode upnp_natt_error;
	std::vector<std::string> localIPAddresses = upnp_natt::getLocalIPAddresses();

	if (localIPAddresses.empty())
	{
		std::cout << "This computer doesn't have any IPv4 addresses." << std::endl;
		getchar();
		return 1;
	}
	if (!upnp_natt::isPrivateIPAddress(localIPAddresses[0]))
	{
		std::cout << "This computer has a global IP address." << std::endl;
		std::cout << localIPAddresses[0] << std::endl;
		getchar();
		return 1;
	}
	std::cout << "Local IP Address: " << localIPAddresses[0] << std::endl;

	// set port mapping info
	port_mapping_info.remoteHost = "";
	port_mapping_info.externalPort = 10429;
	port_mapping_info.protocol = upnp_natt::UDP_PORTMAP;
	port_mapping_info.internalPort = 10429;
	port_mapping_info.internalClient = localIPAddresses[0];
	port_mapping_info.enabled = true;
	port_mapping_info.portMappingDescription = "Port mapping test by UPnPNAT-T";
	port_mapping_info.leaseDuration = 600;

	CoInitializeEx(NULL, 0);

	try
	{
		// get devices
		upnp_natt_error = deviceFinder.getWANConnectionDevices(devices);
		if (upnp_natt_error != upnp_natt::UPNPNATT_OK)
		{
			throw upnp_natt_error;
		}
		firstdevice = devices[0];

		// get device name
		std::string deviceFriendlyName;
		firstdevice.getRootDeviceFriendlyName(deviceFriendlyName);
		std::cout << "Friendly Name: " << deviceFriendlyName << std::endl;

		// get external IP
		std::string externalIPAddress;
		upnp_natt_error = firstdevice.getExternalIPAddress(externalIPAddress);
		switch (upnp_natt_error)
		{
		case upnp_natt::UPNPNATT_OK:
			std::cout << "External IP Address: " << externalIPAddress << std::endl;
			break;
		case upnp_natt::UPNPNATT_COM_ERROR:
			std::cout << "getExternalIP Failed: COM Error: 0x" << std::hex << firstdevice.getLastCOMError() << std::endl;
			firstdevice.clearLastCOMError();
			break;
		case upnp_natt::UPNPNATT_UPNP_DEVICE_ERROR:
			std::cout << "getExternalIP Failed: Device Error: " << firstdevice.getLastUPnPDeviceError() << std::endl;
			firstdevice.clearLastUPnPDeviceError();
			break;
		default:
			std::cout << "getExternalIP Failed: " << UPNP_NATT_ERROR_MESSAGES[upnp_natt_error] << std::endl;
		}

		// add port mapping to the first device
		upnp_natt_error = firstdevice.addPortMapping(port_mapping_info);
		if (upnp_natt_error != upnp_natt::UPNPNATT_OK)
		{
			throw upnp_natt_error;
		}
		std::cout << "Port mapping succeeded." << std::endl;

		// get port mapping info 
		upnp_natt::PortMappingInfo hint;
		hint.remoteHost = "";
		hint.externalPort = 10429;
		hint.protocol = upnp_natt::UDP_PORTMAP;

		upnp_natt::PortMappingInfo out;
		upnp_natt_error = firstdevice.getSpecificPortMappingEntry(hint, out);
		switch (upnp_natt_error)
		{
		case upnp_natt::UPNPNATT_OK:
			std::cout << "RemoteHost: " << out.remoteHost << std::endl
				<< "ExternalPort: " << out.externalPort << std::endl
				<< "PortMappingProtocol: " << out.protocol << std::endl
				<< "InternalPort: " << out.internalPort << std::endl
				<< "InternalClient: " << out.internalClient << std::endl
				<< "PortMappingEnabled: " << (out.enabled ? "True" : "False") << std::endl
				<< "PortMappingDescription: " << out.portMappingDescription << std::endl
				<< "PortMappingLeaseDuration: " << out.leaseDuration << std::endl;
			break;
		case upnp_natt::UPNPNATT_COM_ERROR:
			std::cout << "getSpecificPortMappingEntry Failed: COM Error: 0x" << std::hex << firstdevice.getLastCOMError() << std::endl;
			firstdevice.clearLastCOMError();
			break;
		case upnp_natt::UPNPNATT_UPNP_DEVICE_ERROR:
			std::cout << "getSpecificPortMappingEntry Failed: Device Error: " << std::dec << firstdevice.getLastUPnPDeviceError() << std::endl;
			firstdevice.clearLastUPnPDeviceError();
			break;
		default:
			std::cout << "getSpecificPortMappingEntry Failed: " << UPNP_NATT_ERROR_MESSAGES[upnp_natt_error] << std::endl;
		}

		// delete port mapping from the first device
		upnp_natt_error = firstdevice.deletePortMapping(hint);
		switch (upnp_natt_error)
		{
		case upnp_natt::UPNPNATT_OK:
			std::cout << "Port mapping deleted." << std::endl;
			break;
		case upnp_natt::UPNPNATT_COM_ERROR:
			std::cout << "deletePortMapping Failed: COM Error: 0x" << std::hex << firstdevice.getLastCOMError() << std::endl;
			firstdevice.clearLastCOMError();
			break;
		case upnp_natt::UPNPNATT_UPNP_DEVICE_ERROR:
			std::cout << "deletePortMapping Failed: Device Error: " << std::dec << firstdevice.getLastUPnPDeviceError() << std::endl;
			firstdevice.clearLastUPnPDeviceError();
			break;
		default:
			std::cout << "deletePortMapping Failed: " << UPNP_NATT_ERROR_MESSAGES[upnp_natt_error] << std::endl;
		}
	}
	catch (upnp_natt::ErrorCode upnp_natt_error)
	{

		switch (upnp_natt_error)
		{
		case upnp_natt::UPNPNATT_COM_ERROR:
			std::cout << "COM Error: 0x" << std::hex << firstdevice.getLastCOMError() << std::endl;
			firstdevice.clearLastCOMError();
			break;
		case upnp_natt::UPNPNATT_UPNP_DEVICE_ERROR:
			std::cout << "UPnP Device Error: " << std::dec << firstdevice.getLastUPnPDeviceError() << std::endl;
			firstdevice.clearLastUPnPDeviceError();
			break;
		default:
			std::cout << "Error: " << UPNP_NATT_ERROR_MESSAGES[upnp_natt_error] << std::endl;
			break;
		}
	}

	CoUninitialize();

	std::cout << "Finished." << std::endl;
	getchar();
	return 0;
}
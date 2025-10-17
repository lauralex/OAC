#include <iostream>
#include <string>
#include <Windows.h>

// =================================================================================================
// == IOCTL Definitions
// =================================================================================================
#define IOCTL_TEST_COMMUNICATION          CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_TRIGGER_CR3_THRASH          CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_UNLOAD_DRIVER               CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_TRIGGER_NMI_STACKWALK       CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_INITIALIZE_WFP_MONITOR      CTL_CODE(FILE_DEVICE_UNKNOWN, 0x804, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_DEINITIALIZE_WFP_MONITOR    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x805, METHOD_BUFFERED, FILE_ANY_ACCESS)

// The symbolic link name for the driver.
const wchar_t* G_SYMLINK_NAME = L"\\\\.\\OAC6";

void SendCr3ThrashRequest(HANDLE hDevice)
{
    std::cout << "[!] Sending IOCTL to trigger the CR3 thrash routine. WATCH THE KERNEL DEBUGGER!" << std::endl;
    std::cout << "    > Press Enter to continue..." << std::endl;
    std::cin.ignore(MAXINT, '\n');
    std::cin.get();

    DWORD bytesReturned = 0;
    BOOL  success = DeviceIoControl(
        hDevice,
        IOCTL_TRIGGER_CR3_THRASH,
        nullptr, 0,
        nullptr, 0,
        &bytesReturned,
        nullptr);

    if (!success)
    {
        std::cerr << "[-] DeviceIoControl for CR3 Thrash failed: " << GetLastError() << std::endl;
    }
    else
    {
        std::cout << "[+] IOCTL sent successfully." << std::endl;
    }
}

void TriggerNmiStackwalk(HANDLE hDevice)
{
    std::cout << "[!] Sending IOCTL to trigger an NMI stack walk." << std::endl;
    DWORD bytesReturned = 0;
    BOOL  success = DeviceIoControl(
        hDevice,
        IOCTL_TRIGGER_NMI_STACKWALK,
        nullptr, 0,
        nullptr, 0,
        &bytesReturned,
        nullptr);

    if (!success)
    {
        std::cerr << "[-] DeviceIoControl for NMI Stackwalk failed: " << GetLastError() << std::endl;
    }
    else
    {
        std::cout << "[+] NMI stack walk request sent successfully. Check your kernel debugger for the output." << std::endl;
    }
}

void InitializeWfpMonitorRequest(HANDLE hDevice)
{
    std::cout << "[!] Sending IOCTL to initialize the WFP network monitor." << std::endl;
    DWORD bytesReturned = 0;
    BOOL  success = DeviceIoControl(
        hDevice,
        IOCTL_INITIALIZE_WFP_MONITOR,
        nullptr, 0,
        nullptr, 0,
        &bytesReturned,
        nullptr);

    if (!success)
    {
        std::cerr << "[-] DeviceIoControl for WFP Initialize failed: " << GetLastError() << std::endl;
    }
    else
    {
        std::cout << "[+] WFP network monitor initialized successfully." << std::endl;
    }
}

void DeinitializeWfpMonitorRequest(HANDLE hDevice)
{
    std::cout << "[!] Sending IOCTL to de-initialize the WFP network monitor." << std::endl;
    DWORD bytesReturned = 0;
    BOOL  success = DeviceIoControl(
        hDevice,
        IOCTL_DEINITIALIZE_WFP_MONITOR,
        nullptr, 0,
        nullptr, 0,
        &bytesReturned,
        nullptr);

    if (!success)
    {
        std::cerr << "[-] DeviceIoControl for WFP De-initialize failed: " << GetLastError() << std::endl;
    }
    else
    {
        std::cout << "[+] WFP network monitor de-initialized successfully." << std::endl;
    }
}

void SendUnloadRequest(HANDLE hDevice)
{
    std::cout << "[!] Sending IOCTL to unload the driver." << std::endl;
    DWORD bytesReturned = 0;
    BOOL  success = DeviceIoControl(
        hDevice,
        IOCTL_UNLOAD_DRIVER,
        nullptr, 0,
        nullptr, 0,
        &bytesReturned,
        nullptr);

    if (!success)
    {
        // This error is expected if the driver unloads before DeviceIoControl returns.
        if (GetLastError() != ERROR_SUCCESS)
        {
            std::cerr << "[-] DeviceIoControl for Unload failed: " << GetLastError() << std::endl;
        }
    }
    else
    {
        std::cout << "[+] Unload request sent successfully. The driver should now be disconnected." << std::endl;
    }
}


int main()
{
    std::cout << "=== OAC Client ===" << std::endl;
    std::cout << "[+] Opening handle to the driver..." << std::endl;

    HANDLE hDevice = CreateFileW(
        G_SYMLINK_NAME,
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr);

    if (hDevice == INVALID_HANDLE_VALUE)
    {
        std::cerr << "[-] Failed to open handle to the driver: " << GetLastError() << std::endl;
        std::cerr << "    > Is the driver loaded? (Use kdmapper)" << std::endl;
        std::cerr << "    > Are you running this application as Administrator?" << std::endl;
        system("pause");
        return 1;
    }

    std::cout << "[+] Successfully obtained a handle to the driver: " << hDevice << std::endl;

    bool running = true;
    while (running)
    {
        std::cout << "\n------------------------------------------" << std::endl;
        std::cout << "Select an option:" << std::endl;
        std::cout << "  1. Trigger CR3 Thrash Routine" << std::endl;
        std::cout << "  2. Trigger NMI Stack Walk" << std::endl;
        std::cout << "  3. Initialize WFP Network Monitor" << std::endl;
        std::cout << "  4. De-initialize WFP Network Monitor" << std::endl;
        std::cout << "  5. Unload Driver" << std::endl;
        std::cout << "  0. Exit Client" << std::endl;
        std::cout << "------------------------------------------" << std::endl;
        std::cout << "Your choice: ";

        std::string choice;
        std::getline(std::cin, choice);

        try
        {
            int option = std::stoi(choice);
            switch (option)
            {
            case 1:
                SendCr3ThrashRequest(hDevice);
                break;
            case 2:
                TriggerNmiStackwalk(hDevice);
                break;
            case 3:
                InitializeWfpMonitorRequest(hDevice);
                break;
            case 4:
                DeinitializeWfpMonitorRequest(hDevice);
                break;
            case 5:
                SendUnloadRequest(hDevice);
                running = false; // Exit loop after unload request
                break;
            case 0:
                running = false;
                break;
            default:
                std::cerr << "[-] Invalid option. Please try again." << std::endl;
                break;
            }
        }
        catch (const std::invalid_argument&)
        {
            if (!choice.empty())
            {
                std::cerr << "[-] Invalid input. Please enter a number." << std::endl;
            }
        }
    }

    if (hDevice != INVALID_HANDLE_VALUE)
    {
        CloseHandle(hDevice);
        std::cout << "[+] Handle to driver closed. Exiting." << std::endl;
        Sleep(1000);
    }

    return 0;
}
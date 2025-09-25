#include <iostream>
#include <string>
#include <Windows.h>

// =================================================================================================
// == IOCTL Definitions
// =================================================================================================
#define IOCTL_TEST_COMMUNICATION    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_TRIGGER_CR3_THRASH    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_UNLOAD_DRIVER         CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)

// The symbolic link name for the driver.
const wchar_t* G_SYMLINK_NAME = L"\\\\.\\OAC6";

void SendCr3ThrashRequest(HANDLE hDevice)
{
    std::cout << "[!] Sending IOCTL to trigger the CR3 thrash routine. WATCH THE KERNEL DEBUGGER!" << std::endl;
    std::cout << "    > Press Enter to continue..." << std::endl;
    std::cin.get();

    DWORD bytesReturned = 0;
    BOOL  success       = DeviceIoControl(
        hDevice,
        IOCTL_TRIGGER_CR3_THRASH,
        nullptr, 0,
        nullptr, 0,
        &bytesReturned,
        nullptr);

    if (!success)
    {
        std::cerr << "[-] DeviceIoControl failed: " << GetLastError() << std::endl;
    }
    else
    {
        std::cout << "[+] IOCTL sent successfully." << std::endl;
    }
}

void SendUnloadRequest(HANDLE hDevice)
{
    std::cout << "[!] Sending IOCTL to unload the driver." << std::endl;
    DWORD bytesReturned = 0;
    BOOL  success       = DeviceIoControl(
        hDevice,
        IOCTL_UNLOAD_DRIVER,
        nullptr, 0,
        nullptr, 0,
        &bytesReturned,
        nullptr);
    if (!success)
    {
        std::cerr << "[-] DeviceIoControl failed: " << GetLastError() << std::endl;
    }
    else
    {
        std::cout << "[+] Unload request sent successfully. The driver should now be disconnected." << std::endl;
        std::cout << "[+] Note: The driver code remains in emory until reboot (or manual freeing).\n" << std::endl;

        // Free the handle as the driver is now gone.
        CloseHandle(hDevice);
    }
}


int main()
{
    std::cout << "=== OAC Client ===" << std::endl;

    std::cout << "[+] Opening handle to the driver..." << std::endl;

    HANDLE hDevice = CreateFileW(
        G_SYMLINK_NAME,
        GENERIC_READ | GENERIC_WRITE,
        0,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr);

    if (hDevice == INVALID_HANDLE_VALUE)
    {
        std::cerr << "[-] Failed to open handle to the driver: " << GetLastError() << std::endl;
        std::cerr << "    > Is the driver loaded? (Use kdmapper)" << std::endl;
        std::cerr << "    > Are you running this application as Administrator?" << std::endl;

        // Sleep for a moment to let the user read the error message.
        Sleep(2000);
        return 1;
    }

    std::cout << "[+] Successfully obtained a handle to the driver: " << hDevice << std::endl;

    bool running = true;
    while (running)
    {
        std::cout << "------------------------------------------" << std::endl;
        std::cout << "Select an option:" << std::endl;
        std::cout << "  1. Trigger CR3 Thrash Routine" << std::endl;
        std::cout << "  2. Unload Driver" << std::endl;
        std::cout << "  0. Exit" << std::endl;
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
                SendUnloadRequest(hDevice);
                _FALLTHROUGH;
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
            std::cerr << "[-] Invalid input. Please enter a number." << std::endl;
        }
    }

    CloseHandle(hDevice);
    std::cout << "[+] Handle to driver closed. Exiting." << std::endl;

    Sleep(2000); // Sleep for a moment to let the user read the exit message.

    return 0;
}

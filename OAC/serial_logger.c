/**
 * @file serial_logger.c
 * @brief A simple serial logger for low-level debugging.
 *
 * This module provides a basic serial logging mechanism suitable for
 * low-level debugging in environments where standard libraries are unavailable.
 * It initializes a UART port and provides functions to send formatted log messages.
 *
 * The logger supports a limited set of format specifiers:
 * - %s: String
 * - %d, %i: Signed decimal integer
 * - %u: Unsigned decimal integer
 * - %x, %X: Unsigned hexadecimal integer (lowercase/uppercase)
 * - %p: Pointer (as hexadecimal)
 * - %%: Literal percent sign
 *
 * The implementation avoids dynamic memory allocation and is designed to be
 * safe against buffer overflows by using fixed-size buffers and careful formatting.
 *
 * Note: This code is intended for educational purposes and may require adaptation
 * for use in production environments, especially regarding hardware specifics
 * and concurrency considerations.
 */

#include "serial_logger.h"
#include "globals.h"

#include <intrin.h>
#include <stdarg.h>
#include <ntddk.h>

/**
 * @brief Enable `DEBUG_MODE` to activate serial logging.
 */
#define DEBUG_MODE 0

static KSPIN_LOCK LogLock = {0};


/***************************************************
 ***************************************************
 **                                               **
 **                 UART Offsets                  **
 **                                               **
 ***************************************************
 ***************************************************/

#define COM1_PORT           0x3F8   // COM1 base port
#define UART_THR_OFFSET     0x00    // Transmit Holding Register offset
#define UART_DLL_OFFSET     0x00    // Divisor Latch Low offset
#define UART_DLM_OFFSET     0x01    // Divisor Latch High offset
#define UART_IER_OFFSET     0x01    // Interrupt Enable Register offset
#define UART_FCR_OFFSET     0x02    // FIFO Control Register offset
#define UART_LCR_OFFSET     0x03    // Line Control Register offset
#define UART_MCR_OFFSET     0x04    // Modem Control Register offset
#define UART_LSR_OFFSET     0x05    // Line Status Register offset

#define UART_IER_DISABLED   0x00    // Disable all interrupts
#define UART_FCR_FIFO_SETUP 0xC7    // Enable FIFO, clear them, with 14-byte threshold
#define UART_LCR_DLAB       0x80    // Divisor Latch Access Bit
#define UART_LCR_8N1        0x03    // 8 bits, no parity, one stop bit
#define UART_MCR_OUT2       0x08    // OUT2 bit in Modem Control Register
#define UART_LSR_THRE       0x20    // Transmitter Holding Register Empty


VOID LoggerInit(VOID)
{
#if DEBUG_MODE
    /***************************************************
     ***************************************************
     **                                               **
     **           UART initialization code            **
     **                                               **
     ***************************************************
     ***************************************************/

    // Disable Interrupts in the UART by clearing
    // the Interrupt Enable Register (IER).
    __outbyte(COM1_PORT + UART_IER_OFFSET, UART_IER_DISABLED);

    // Set baud rate to 9600
    __outbyte(COM1_PORT + UART_LCR_OFFSET, UART_LCR_DLAB);
    __outbyte(COM1_PORT + UART_DLL_OFFSET, 0x0C);
    __outbyte(COM1_PORT + UART_DLM_OFFSET, 0x00);

    // Set line control: 8 bits, no parity, one stop bit
    __outbyte(COM1_PORT + UART_LCR_OFFSET, UART_LCR_8N1);

    // Enable and clear the FIFOs
    __outbyte(COM1_PORT + UART_FCR_OFFSET, UART_FCR_FIFO_SETUP);

    // Set the Modem Control Register (MCR) to 0x08
    __outbyte(COM1_PORT + UART_MCR_OFFSET, UART_MCR_OUT2);
#endif
}

/**
 * @internal
 * @brief Reverses a string in-place.
 *
 * @param[in,out] String  The null-terminated string to reverse.
 */
static VOID LogpReverseString(
    _Inout_ PCHAR String
)
{
    PCHAR Start = String;
    PCHAR End   = Start;
    char  Temp;

    // Find the end of the string
    while (*End)
    {
        End++;
    }
    End--; // Point to the last character, not the null terminator

    // Swap characters from the outside in
    while (Start < End)
    {
        Temp   = *Start;
        *Start = *End;
        *End   = Temp;
        Start++;
        End--;
    }
}

/**
 * @internal
 * @brief Converts an unsigned 64-bit integer to a string.
 *
 * This is a safe implementation that respects the provided buffer size.
 *
 * @param[in]  Value         The integer value to convert.
 * @param[out] Buffer        The destination buffer for the string.
 * @param[in]  BufferSize    The size of the destination buffer.
 * @param[in]  Base          The numerical base (e.g., 10 for decimal, 16 for hex).
 * @param[in]  Uppercase     If TRUE, use uppercase letters for hexadecimal digits.
 *
 * @return The number of characters written, or 0 on failure (e.g., buffer too small).
 */
static SIZE_T LogpIntegerToString(
    _In_ UINT64  Value,
    _Out_ PCHAR  Buffer,
    _In_ size_t  BufferSize,
    _In_ int     Base,
    _In_ BOOLEAN Uppercase
)
{
    SIZE_T      Index  = 0;
    const char* Digits = Uppercase
                             ? "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                             : "0123456789abcdefghijklmnopqrstuvwxyz";

    if (Base < 2 || Base > 36)
    {
        return 0;
    }

    // Handle 0 explicitly, otherwise the loop won't run
    if (Value == 0)
    {
        if (BufferSize > 1)
        {
            Buffer[0] = '0';
            Buffer[1] = '\0';
            return 1;
        }
        return 0;
    }

    while (Value != 0)
    {
        if (Index >= (BufferSize - 1))
        {
            // Not enough space
            return 0;
        }
        Buffer[Index++] = Digits[Value % Base];
        Value /= Base;
    }

    Buffer[Index] = '\0';
    LogpReverseString(Buffer);

    return Index;
}

/**
 * @brief Formats a string using a va_list of arguments.
 * 
 * @internal
 * This is the core formatting engine, designed to be a safe replacement for vsnprintf.
 * It supports a subset of standard format specifiers: %s, %d, %i, %u, %x, %X, %p, %%.
 * The output is always null-terminated, even on truncation.
 * @endinternal
 *
 * @param[out] Buffer      The destination buffer for the formatted string.
 * @param[in]  BufferSize  The total size of the destination buffer, including the null terminator.
 * @param[in]  Format      The format control string.
 * @param[in]  Args        The va_list of arguments to format.
 */
static VOID SerialLoggerFormatV(
    _Out_ PCHAR  Buffer,
    _In_ size_t  BufferSize,
    _In_ PCSTR   Format,
    _In_ va_list Args
)
{
    size_t BufferIndex = 0;
    PCHAR  PFormat     = (PCHAR)Format;

    if (Buffer == NULL || BufferSize == 0)
    {
        return;
    }

    while (*PFormat != '\0' && BufferIndex < (BufferSize - 1))
    {
        if (*PFormat != '%')
        {
            Buffer[BufferIndex++] = *PFormat++;
            continue;
        }

        PFormat++; // Move past the '%'

        char  TempNumberBuffer[65] = {0}; // Sufficient for 64-bit integer in binary + null
        PCHAR StringToCopy         = NULL;

        switch (*PFormat)
        {
        case 's':
            {
                StringToCopy = va_arg(Args, PCHAR);
                if (StringToCopy == NULL)
                {
                    StringToCopy = "(null)";
                }
                break;
            }
        case 'd':
        case 'i':
            {
                int IntValue = va_arg(Args, int);
                if (IntValue < 0)
                {
                    Buffer[BufferIndex++] = '-';
                    if (BufferIndex >= (BufferSize - 1)) goto End;
                    LogpIntegerToString((UINT64)-(long long)IntValue, TempNumberBuffer, sizeof(TempNumberBuffer), 10,
                                        FALSE);
                }
                else
                {
                    LogpIntegerToString(IntValue, TempNumberBuffer, sizeof(TempNumberBuffer), 10, FALSE);
                }
                StringToCopy = TempNumberBuffer;
                break;
            }
        case 'u':
            {
                unsigned int UintValue = va_arg(Args, unsigned int);
                LogpIntegerToString(UintValue, TempNumberBuffer, sizeof(TempNumberBuffer), 10, FALSE);
                StringToCopy = TempNumberBuffer;
                break;
            }
        case 'x':
        case 'X':
            {
                unsigned int HexValue = va_arg(Args, unsigned int);
                LogpIntegerToString(HexValue, TempNumberBuffer, sizeof(TempNumberBuffer), 16, (*PFormat == 'X'));
                StringToCopy = TempNumberBuffer;
                break;
            }
        case 'p':
            {
                UINT64 PtrValue = (UINT64)va_arg(Args, void*);
                LogpIntegerToString(PtrValue, TempNumberBuffer, sizeof(TempNumberBuffer), 16, TRUE);
                StringToCopy = TempNumberBuffer;
                break;
            }
        case '%':
            {
                Buffer[BufferIndex++] = '%';
                break;
            }
        default:
            {
                Buffer[BufferIndex++] = '%';
                if (BufferIndex < (BufferSize - 1))
                {
                    Buffer[BufferIndex++] = *PFormat;
                }
                break;
            }
        }

        if (StringToCopy)
        {
            while (*StringToCopy != '\0' && BufferIndex < (BufferSize - 1))
            {
                Buffer[BufferIndex++] = *StringToCopy++;
            }
        }

        PFormat++; // Move to the next character in the format string
    }

End:
    Buffer[BufferIndex] = '\0';
}

/**
 * @internal
 * @brief Sends a single character to the serial port.
 *
 * This function waits until the UART is ready to accept a new character
 * before sending it. It uses a polling mechanism on the Line Status Register (LSR).
 *
 * @param[in] Ch The character to send.
 */
VOID UartPutchar(
    _In_ CHAR Ch
)
{
    // Poll the Line Status Register (LSR) and wait until
    // Transmitter Holding Register (THR) is empty.
    while ((__inbyte(COM1_PORT + UART_LSR_OFFSET) & UART_LSR_THRE) == 0)
    {
        // Wait..., let's use mmpause to prevent busy waiting
        _mm_pause();
    }

    // When the THR is empty, write the character to the THR.
    __outbyte(COM1_PORT + UART_THR_OFFSET, Ch);
}

/**
 * @internal
 * @brief Writes a null-terminated string to the serial port.
 *
 * @param[in] String The string to be written.
 */
static VOID LogpWriteString(
    _In_ PCSTR String
)
{
    PCSTR PCharacter = String;
    while (*PCharacter != '\0')
    {
        UartPutchar(*PCharacter++);
    }
}

/**
 * @brief Formats a string and writes it to the serial port, followed by a newline.
 *
 * This function is the primary interface for logging. It safely formats the message
 * into a stack buffer and then transmits it over the configured UART port.
 * It is a variadic function, accepting a format string and arguments similar to printf.
 *
 * @param[in] Format The format control string.
 * @param[in] ...    The arguments to format.
 */
VOID SerialLoggerWrite(
    _In_z_ _Printf_format_string_ PCSTR Format,
    _In_ ...
)
{
#if DEBUG_MODE
    // A buffer on the stack to hold the formatted log message.
    // Its size is controlled by a single, clear constant.
    CHAR    LogBuffer[MAX_LOG_MESSAGE_LENGTH] = {0};
    va_list Args;

    // Format the string safely using the new, robust formatting function.
    // We pass the buffer and its size to prevent any possibility of an overflow.
    va_start(Args, Format);
    SerialLoggerFormatV(LogBuffer, sizeof(LogBuffer), Format, Args);
    va_end(Args);

    // Prepend the processor number to the log message.
    CHAR ProcessorBuffer[10] = {0};
    LogpIntegerToString(KeGetCurrentProcessorNumberEx(NULL), ProcessorBuffer, sizeof(ProcessorBuffer), 10, TRUE);

    //KeStallExecutionProcessor(500);

    // Write the resulting string and a CRLF sequence to the serial port.
    KIRQL OldIrql;
    KeAcquireSpinLock(&LogLock, &OldIrql);
    LogpWriteString(ProcessorBuffer);
    LogpWriteString(LogBuffer);
    LogpWriteString("\r\n");
    KeReleaseSpinLock(&LogLock, OldIrql);
#else
    UNREFERENCED_PARAMETER(Format);
#endif
}

/**
 * @brief Logs anything from an ISR.
 *
 * This function is intended to be called from an ISR.
 *
 * @param[in] Something A parameter that can be used to log some info.
 */
VOID SerialLoggerIsr(
    _In_ UINT64 Something
)
{
#if DEBUG_MODE
    SerialLoggerWrite("Logging from ISR. Info: %p", Something);
#else
    UNREFERENCED_PARAMETER(Something);
#endif
}

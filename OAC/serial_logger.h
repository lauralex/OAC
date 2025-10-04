#pragma once
#include <ntdef.h>

// A configurable constant for the maximum log message size.
#define MAX_LOG_MESSAGE_LENGTH 256


/**
 * @brief Formats a string using a va_list of arguments.
 *
 * This is the core formatting engine, designed to be a safe replacement for vsnprintf.
 * It supports a subset of standard format specifiers: %s, %d, %i, %u, %x, %X, %p, %%.
 * The output is always null-terminated, even on truncation.
 *
 * @param[out] Buffer      The destination buffer for the formatted string.
 * @param[in]  BufferSize  The total size of the destination buffer, including the null terminator.
 * @param[in]  Format      The format control string.
 * @param[in]  Args        The va_list of arguments to format.
 */
VOID SerialLoggerFormatV(
    _Out_ PCHAR  Buffer,
    _In_ size_t  BufferSize,
    _In_ PCSTR   Format,
    _In_ va_list Args
);

VOID LoggerInit(VOID);


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
);


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
    _In_ PCSTR Format,
    _In_ ...
);

/**
 * @brief Logs anything from an ISR.
 *
 * This function is intended to be called from an ISR.
 *
 * @param[in] Something A parameter that can be used to log some info.
 */
VOID SerialLoggerIsr(
    _In_ UINT64 Something
);

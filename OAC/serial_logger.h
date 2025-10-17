/**
 * @file serial_logger.h
 * @brief A simple serial logger for debugging purposes.
 *
 * This module provides a basic logging mechanism that outputs formatted messages
 * to a serial port (COM1 by default). It is designed for use in low-level system
 * programming, such as operating system kernels or embedded systems, where standard
 * I/O facilities may not be available.
 *
 * The logger supports a subset of standard format specifiers and ensures that all
 * output is null-terminated. It is safe to use in interrupt service routines (ISRs).
 *
 * Note: This implementation assumes a standard PC architecture with a 16550 UART.
 */

#pragma once
#include <ntdef.h>

// A configurable constant for the maximum log message size.
#define MAX_LOG_MESSAGE_LENGTH 256


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
    _In_z_ _Printf_format_string_ PCSTR Format,
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

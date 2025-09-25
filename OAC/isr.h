#pragma once

// Our assembly ISR. Tells the C compiler it exists elsewhere.
extern void PageFaultIsr(void); // Defined in isr.asm

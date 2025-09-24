.CODE

EXTERN G_OriginalCr3 : QWORD  ; Import the global variable from C

; This is our custom Interrupt Service Routine (ISR) for the Page Fault.
; It's extremely simple to avoid any memory access.
; It receives no parameters in the traditional sense. It just needs to
; restore CR3 and return.
PageFaultIsr PROC
    mov rax, G_OriginalCr3
	mov cr3, rax           ; Restore the original CR3 value
	iretq                  ; Return from the interrupt
PageFaultIsr ENDP

END
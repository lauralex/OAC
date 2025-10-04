.CODE

; _MACHINE_FRAME: Represents the stack frame pushed by the CPU on an interrupt/exception.
_MACHINE_FRAME STRUC
    $ErrorCode QWORD ?
    $Rip       QWORD ?
    $Cs        QWORD ?
    $Rflags    QWORD ?
    $Rsp       QWORD ?
    $Ss        QWORD ?
_MACHINE_FRAME ENDS

EXTERN G_OriginalCr3		: QWORD  ; Import the global variable from C
EXTERN SerialLoggerIsr      : PROC	 ; Import the logging function from C
EXTERN GetInstructionLength : PROC   ; Import the instruction length function from C

; This is our custom Interrupt Service Routine (ISR) for the Page Fault.
; It's extremely simple to avoid any memory access.
; It receives no parameters in the traditional sense. It just needs to
; restore CR3 and return.
PageFaultIsr PROC
	; === Save Current State for Potential Recovery ===
    push rax
    push rcx
    push rdx
    push rbx
    push rsi
    push rdi
    push r8
    push r9
    push r10
    push r11
    push r12
    push r13
    push r14
    push r15
    push rbp
    sub rsp, 20h
    ; now rsp is at 98h

    mov rax, G_OriginalCr3
	mov cr3, rax           ; Restore the original CR3 value


    mov rcx, [rsp + 98h + _MACHINE_FRAME.$Rip] ; Address of the faulting instruction]
	call GetInstructionLength

	add byte ptr [rsp + 98h + _MACHINE_FRAME.$Rip], al ; Skip the faulting instruction

    ; === Restore Registers and Return ===
    add rsp, 20h
    pop rbp
    pop r15
    pop r14
    pop r13
    pop r12
    pop r11
    pop r10
    pop r9
    pop r8
    pop rdi
    pop rsi
    pop rbx
    pop rdx
    pop rcx
    pop rax

	; pop error code from the stack (pushed by CPU)
	add rsp, 8             ; Adjust stack to remove error code
	iretq                  ; Return from the interrupt
PageFaultIsr ENDP

END
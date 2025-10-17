.CODE

; =========================================================================================
; == Structure Definitions (Mirrors C Headers)
; =========================================================================================
; These structures must be defined here so the assembler understands the layout
; of the global G_SafeUnwindContext variable imported from C.

; Define M128A for XMM registers
M128A STRUC
    $Low  QWORD ?
    $High QWORD ?
M128A ENDS

XSAVE_FORMAT STRUC
    $ControlWord     WORD ?
    $StatusWord      WORD ?
    $TagWord         BYTE ?
    $Reserved1       BYTE ?
    $ErrorOpcode     WORD ?
    $ErrorOffset    DWORD ?
    $ErrorSelector   WORD ?
    $Reserved2       WORD ?
    $DataOffset     DWORD ?
    $DataSelector    WORD ?
    $Reserved3       WORD ?
    $MxCsr          DWORD ?
    $MxCsr_Mask     DWORD ?
    $FloatRegisters M128A  8 DUP(<>)  ; ST0 through ST7
    $XmmRegisters   M128A 16 DUP(<>)  ; XMM0 through XMM15
    $Reserved4      BYTE  96 DUP(?)
XSAVE_FORMAT ENDS

; Define the CONTEXT structure, mirroring the one in winnt.h for x64
CONTEXT STRUC
    $P1Home         QWORD ?
    $P2Home         QWORD ?
    $P3Home         QWORD ?
    $P4Home         QWORD ?
    $P5Home         QWORD ?
    $P6Home         QWORD ?
    $ContextFlags   DWORD ?
    $MxCsr          DWORD ?
    $SegCs           WORD ?
    $SegDs           WORD ?
    $SegEs           WORD ?
    $SegFs           WORD ?
    $SegGs           WORD ?
    $SegSs           WORD ?
    $EFlags         DWORD ?
    $Dr0            QWORD ?
    $Dr1            QWORD ?
    $Dr2            QWORD ?
    $Dr3            QWORD ?
    $Dr6            QWORD ?
    $Dr7            QWORD ?
    $Rax            QWORD ?
    $Rcx            QWORD ?
    $Rdx            QWORD ?
    $Rbx            QWORD ?
    $Rsp            QWORD ?
    $Rbp            QWORD ?
    $Rsi            QWORD ?
    $Rdi            QWORD ?
    $R8             QWORD ?
    $R9             QWORD ?
    $R10            QWORD ?
    $R11            QWORD ?
    $R12            QWORD ?
    $R13            QWORD ?
    $R14            QWORD ?
    $R15            QWORD ?
    $Rip            QWORD ?
    $FltSave                XSAVE_FORMAT <>   ; Union for XMM_SAVE_AREA32
    $VectorRegister         M128A 26 DUP(<>)
    $VectorControl          QWORD ?
    $DebugControl           QWORD ?
    $LastBranchToRip        QWORD ?
    $LastBranchFromRip      QWORD ?
    $LastExceptionToRip     QWORD ?
    $LastExceptionFromRip   QWORD ?
CONTEXT ENDS

; Define our safe unwind context structure
SAFE_UNWIND_CONTEXT STRUC
    $FaultOccurred DWORD ?
    ALIGN 16
    $RegisterState CONTEXT <>
SAFE_UNWIND_CONTEXT ENDS

; _MACHINE_FRAME: Represents the stack frame pushed by the CPU on an interrupt/exception.
_MACHINE_FRAME STRUC
    $ErrorCode QWORD ?
    $Rip       QWORD ?
    $Cs        QWORD ?
    $Rflags    QWORD ?
    $Rsp       QWORD ?
    $Ss        QWORD ?
_MACHINE_FRAME ENDS


; === Import global variables and functions from C ===
EXTERN G_SafeUnwindContext              : PTR SAFE_UNWIND_CONTEXT
EXTERN RtlVirtualUnwind                 : PROC
EXTERN KeGetCurrentProcessorNumberEx    : PROC
EXTERN SerialLoggerIsr                  : PROC

; =========================================================================================
; == Custom Page Fault ISR for Safe Recovery
; =========================================================================================
PageFaultRecoveryIsr PROC
    ; --- Modify the on-stack machine frame for iretq ---
    ; RSP points to the _MACHINE_FRAME pushed by the CPU.
    mov r15, rsp ; Use r15 as a temporary pointer to the frame.

    sub rsp, 28h

    ; Get current processor index.
    xor     ecx, ecx ; Clear rcx for the call
    call    KeGetCurrentProcessorNumberEx
    mov eax, eax     ; zero-extend to rax

    ; Calculate the offset: index * sizeof(SAFE_UNWIND_CONTEXT)
    imul rax, SIZEOF SAFE_UNWIND_CONTEXT

    ; Add the offset to the base address to get the address of the element
    lea r14, [G_SafeUnwindContext]
    add r14, rax

    ; Mark that a fault has occurred in our global context.
    mov SAFE_UNWIND_CONTEXT.$FaultOccurred[r14], 1

    ; Also, log the RIP where the fault occurred (optional).
    mov     rcx, [r15 + _MACHINE_FRAME.$Rip]
    call    SerialLoggerIsr

    ; Also log the CR2 register (faulting address).
    mov     rcx, cr2
    call    SerialLoggerIsr

    ; Also log the error code.
    mov     rcx, [r15 + _MACHINE_FRAME.$ErrorCode]
    call    SerialLoggerIsr
    
    ; Overwrite the return RIP with our recovery RIP.
    mov rax, SAFE_UNWIND_CONTEXT.$RegisterState.$Rip[r14]
    mov [r15 + _MACHINE_FRAME.$Rip], rax

    ; Overwrite the return RSP with our saved stack pointer.
    mov rax, SAFE_UNWIND_CONTEXT.$RegisterState.$Rsp[r14]
    mov [r15 + _MACHINE_FRAME.$Rsp], rax
    
    ; Overwrite the return RFLAGS.
    mov eax, SAFE_UNWIND_CONTEXT.$RegisterState.$EFlags[r14]
    mov dword ptr [r15 + _MACHINE_FRAME.$Rflags], eax

    ; Overwrite segment registers (usually unchanged, but good practice).
    mov ax, SAFE_UNWIND_CONTEXT.$RegisterState.$SegCs[r14]
    mov word ptr [r15 + _MACHINE_FRAME.$Cs], ax
    mov ax, SAFE_UNWIND_CONTEXT.$RegisterState.$SegSs[r14]
    mov word ptr [r15 + _MACHINE_FRAME.$Ss], ax

    ; --- Restore General-Purpose Registers ---
    ; These were not saved by the CPU and must be restored from our global context.
    mov rax, 0C0000002h ; STATUS_PAGE_FAULT_IN_NONPAGED_AREA
    mov rcx, SAFE_UNWIND_CONTEXT.$RegisterState.$Rcx[r14]
    mov rdx, SAFE_UNWIND_CONTEXT.$RegisterState.$Rdx[r14]
    mov rbx, SAFE_UNWIND_CONTEXT.$RegisterState.$Rbx[r14]
    mov rbp, SAFE_UNWIND_CONTEXT.$RegisterState.$Rbp[r14]
    mov rsi, SAFE_UNWIND_CONTEXT.$RegisterState.$Rsi[r14]
    mov rdi, SAFE_UNWIND_CONTEXT.$RegisterState.$Rdi[r14]
    mov  r8, SAFE_UNWIND_CONTEXT.$RegisterState.$R8 [r14]
    mov  r9, SAFE_UNWIND_CONTEXT.$RegisterState.$R9 [r14]
    mov r10, SAFE_UNWIND_CONTEXT.$RegisterState.$R10[r14]
    mov r11, SAFE_UNWIND_CONTEXT.$RegisterState.$R11[r14]
    mov r12, SAFE_UNWIND_CONTEXT.$RegisterState.$R12[r14]
    mov r13, SAFE_UNWIND_CONTEXT.$RegisterState.$R13[r14]
    mov r15, SAFE_UNWIND_CONTEXT.$RegisterState.$R15[r14]
    ; this should be last since we use r14 above.
    mov r14, SAFE_UNWIND_CONTEXT.$RegisterState.$R14[r14]

    ; Restore the stack pointer.
    add rsp, 28h

    ; pop the error code from the stack (pushed by CPU)
    add rsp, 8 ; Adjust stack to remove error code

    ; The iretq instruction will now use the modified frame on the stack.
    ; It will pop RIP, CS, RFLAGS, RSP, and SS, effectively jumping to our
    ; RecoveryLabel with the correct stack and processor flags.
    iretq
PageFaultRecoveryIsr ENDP

; =========================================================================================
; == Safe Wrapper for RtlVirtualUnwind
; =========================================================================================
SafeRtlVirtualUnwind PROC
    sub rsp, 78h

    ; Get current processor index.
    mov [rsp + 30h], rcx ; Save rcx since we'll use it.
    xor     ecx, ecx     ; Clear rcx for the call
    call    KeGetCurrentProcessorNumberEx
    mov eax, eax         ; zero-extend to rax
    mov rcx, [rsp + 30h] ; Restore rcx

    ; Calculate the offset: index * sizeof(SAFE_UNWIND_CONTEXT)
    imul rax, SIZEOF SAFE_UNWIND_CONTEXT

    ; Add the offset to the base address to get the address of the element
    lea r10, [G_SafeUnwindContext]
    add r10, rax

    ; Save r10 into stack for later use
    mov [rsp + 60h], r10

    ; === Save Current State for Potential Recovery ===
    mov SAFE_UNWIND_CONTEXT.$RegisterState.$Rax[r10], rax
    mov SAFE_UNWIND_CONTEXT.$RegisterState.$Rcx[r10], rcx
    mov SAFE_UNWIND_CONTEXT.$RegisterState.$Rdx[r10], rdx
    mov SAFE_UNWIND_CONTEXT.$RegisterState.$Rbx[r10], rbx
    mov SAFE_UNWIND_CONTEXT.$RegisterState.$Rsi[r10], rsi
    mov SAFE_UNWIND_CONTEXT.$RegisterState.$Rdi[r10], rdi
    mov SAFE_UNWIND_CONTEXT.$RegisterState.$R8 [r10],  r8
    mov SAFE_UNWIND_CONTEXT.$RegisterState.$R9 [r10],  r9
    mov SAFE_UNWIND_CONTEXT.$RegisterState.$R10[r10], r10
    mov SAFE_UNWIND_CONTEXT.$RegisterState.$R11[r10], r11
    mov SAFE_UNWIND_CONTEXT.$RegisterState.$R12[r10], r12
    mov SAFE_UNWIND_CONTEXT.$RegisterState.$R13[r10], r13
    mov SAFE_UNWIND_CONTEXT.$RegisterState.$R14[r10], r14
    mov SAFE_UNWIND_CONTEXT.$RegisterState.$R15[r10], r15
    mov SAFE_UNWIND_CONTEXT.$RegisterState.$Rsp[r10], rsp
    mov SAFE_UNWIND_CONTEXT.$RegisterState.$Rbp[r10], rbp

    ; Save CS, SS, and RFLAGS
    mov ax, cs
    mov SAFE_UNWIND_CONTEXT.$RegisterState.$SegCs[r10], ax
    mov ax, ss
    mov SAFE_UNWIND_CONTEXT.$RegisterState.$SegSs[r10], ax
    pushfq
    pop rax
    mov SAFE_UNWIND_CONTEXT.$RegisterState.$EFlags[r10], eax

    ; Save the recovery RIP.
    lea rax, [RecoveryLabel]
    mov SAFE_UNWIND_CONTEXT.$RegisterState.$Rip[r10], rax

    ; Clear the fault indicator.
    mov SAFE_UNWIND_CONTEXT.$FaultOccurred[r10], 0

    mov     rax, [rsp + 78h + 40h] ; eighth parameter
    mov     [rsp + 38h], rax

    mov     rax, [rsp + 78h + 38h] ; seventh parameter
    mov     [rsp + 30h], rax

    mov     rax, [rsp + 78h + 30h] ; sixth parameter
    mov     [rsp + 28h], rax

    mov     rax, [rsp + 78h + 28h] ; fifth parameter
    mov     [rsp + 20h], rax

    mov     r9,  r9                 ; fourth parameter
    mov     r8,  r8                 ; third parameter
    mov     rdx, rdx                ; second parameter
    mov     rcx, rcx                ; first parameter

    ; Call the C helper to perform the IDT swap and the actual unwind.
    call    RtlVirtualUnwind

RecoveryLabel:
    ; Execution resumes here either normally or via a JMP from the ISR.
    mov r10, [rsp + 60h] ; Retrieve r10 (context pointer)
    cmp     SAFE_UNWIND_CONTEXT.$FaultOccurred[r10], 1 ; Check if a fault occurred
    jne     NoFault
    
    ; Fault occurred. Return the specific page fault status code.
    mov     eax, 0C0000002h ; STATUS_PAGE_FAULT_IN_NONPAGED_AREA

NoFault:
    ; Normal return or recovery complete. The return value is already in RAX.
    
    add rsp, 78h
    ret

SafeRtlVirtualUnwind ENDP

END
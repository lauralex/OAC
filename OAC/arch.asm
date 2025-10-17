.CODE

_str PROC
	str word ptr [rcx]
	ret
_str ENDP

_invd PROC
	invd
	ret
_invd ENDP

GetRsp PROC
	lea rax, [rsp + 08h]
	ret
GetRsp ENDP

SetTrapFlag PROC
	pushfq
	mov rax, [rsp]
	or rax, 100h
	mov [rsp], rax
	popfq
	ret
SetTrapFlag ENDP

ClearTrapFlag PROC
	pushfq
	mov rax, [rsp]
	and rax, 0FFFFFFFFFFFFFEFFh
	mov [rsp], rax
	popfq
	ret
ClearTrapFlag ENDP

SetWriteDataBreakpoint PROC
	mov dr0, rcx
	mov rax, 90303h
	mov dr7, rax
	ret
SetWriteDataBreakpoint ENDP

ClearDataBreakpoints PROC
	xor rax, rax
	mov dr0, rax
	mov dr1, rax
	mov dr2, rax
	mov dr3, rax
	mov dr6, rax
	mov dr7, rax
	ret
ClearDataBreakpoints ENDP

END
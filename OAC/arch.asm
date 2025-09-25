.CODE

_str PROC
	str word ptr [rcx]
	ret
_str ENDP

_invd PROC
	invd
	ret
_invd ENDP

END
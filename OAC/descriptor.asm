.code

OacStoreGdtr PROC
    sgdt fword ptr [rcx]
    ret
OacStoreGdtr ENDP

END

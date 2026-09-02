.code

; rcx = buf (passed from main, Windows x64 ABI first arg)
pushtest PROC
    push rax
    push rax
    push rax
    mov  rax, 12345679h
    mov  rax, 12345678h
    push rax

    push rbx
    mov  rbx, 12345677h
    pop  rbx

    push rcx
    mov  rcx, 12345676h
    pop  rcx

    pop  rax
    pop  rax
    pop  rax
    pop  rax
    ; 写 1 字节到 buf[0]
    mov  byte ptr [rcx], 0ABh

    ; 写 4 字节到 buf[1]
    mov  dword ptr [rcx+1], 0DEADBEEFh

    ; mov rcx 立即数
    mov  rcx, 123456789ABCDEFh

    ret
pushtest ENDP

END

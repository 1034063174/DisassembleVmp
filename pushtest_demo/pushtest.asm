.code

; rcx = buf (passed from main, Windows x64 ABI first arg)
pushtest PROC


    push rax

    mov  rax, 12345679h
    mov  rax, 12345678h
    add   rcx ,1
    mov  qword ptr [rcx], rax

    sub   rcx ,1
    pop rax

    mov  byte ptr [rcx], 0ABh


    mov  dword ptr [rcx+1], 0DEADBEEFh


    mov  rcx, 123456789ABCDEFh

    ret



pushtest ENDP

END

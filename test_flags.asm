
        
    global    _start

    section   .text
_start:
        
        mov rax, 18446744073709551614
        shl rax, 1
        
        pushf
        mov       rax, 60                 ; system call for exit
        pop       rdi                     ; exit code rflags
        syscall                           ; invoke operating system to exit
        
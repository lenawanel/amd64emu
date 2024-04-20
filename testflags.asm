mov rax, 1
cmp rax, rax
pushf
mov       rax, 60                 ; system call for exit
pop       rdi                     ; exit code 0
syscall                           ; invoke operating system to exit
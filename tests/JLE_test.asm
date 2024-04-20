
    global    _start

    section   .text
_start:
    xor rax, rax
    cmp rax, 1
    jle thirtytwo_bit
    mov       rax, 60                 ; system call for exit
    mov       rdi, 1                  ; exit code 0
    syscall                           ; invoke operating system to exit

thirtytwo_bit:
    xor eax, eax
    cmp eax, 1
    jle sixteen_bit
    mov       rax, 60                 ; system call for exit
    mov       rdi, 1                  ; exit code 0
    syscall                           ; invoke operating system to exit

sixteen_bit:
    xor ax, ax
    cmp ax, 1
    jle eight_bit
    mov       rax, 60                 ; system call for exit
    mov       rdi, 1                  ; exit code 0
    syscall                           ; invoke operating system to exit
eight_bit:
    xor al, al
    cmp al, 1
    jle sixtyfoure_bit
    mov       rax, 60                 ; system call for exit
    mov       rdi, 1                  ; exit code 0
    syscall                           ; invoke operating system to exit


sixtyfoure_bit:
    mov rax, 1
    cmp rax, 1
    jle thirtytwoe_bit
    mov       rax, 60                 ; system call for exit
    mov       rdi, 1                  ; exit code 0
    syscall                           ; invoke operating system to exit

thirtytwoe_bit:
    mov eax, 1
    cmp eax, 1
    jle sixteene_bit
    mov       rax, 60                 ; system call for exit
    mov       rdi, 1                  ; exit code 0
    syscall                           ; invoke operating system to exit

sixteene_bit:
    mov ax, 1
    cmp ax, 1
    jle eighte_bit
    mov       rax, 60                 ; system call for exit
    mov       rdi, 1                  ; exit code 0
    syscall                           ; invoke operating system to exit
eighte_bit:
    mov al, 1
    cmp al, 1
    jle success
    mov       rax, 60                 ; system call for exit
    mov       rdi, 1                  ; exit code 0
    syscall                           ; invoke operating system to exit

success:
    mov       rax, 60                 ; system call for exit
    xor       rdi, rdi                ; exit code 0
    syscall                           ; invoke operating system to exit

BITS 64
CPU X64

%macro prologue 1
        push rbp
        mov rbp, rsp
        sub rsp, %1
%endmacro

%macro epilogue 1
        add rsp, %1
        pop rbp
        ret
%endmacro

%macro exit_program 1
        mov rax, syscall_exit
        mov rdi, %1
        syscall
%endmacro

%define syscall_exit 60
%define syscall_write 1
%define syscall_fork 57
%define syscall_setsid 112
%define syscall_chdir 80
%define syscall_close 3
%define syscall_nanosleep 35
%define syscall_execve 59
%define syscall_stat 4

%define stdin 0
%define stdout 1
%define stderr 2

%define seconds_to_sleep 5

section .rodata
root_dir db "/", 0

env_display db "DISPLAY=:0", 0

xauth_pattern db "XAUTHORITY="
xauth_pattern_len equ $-xauth_pattern

minimum_xauth_value_len equ 18
minimum_xauth_len equ xauth_pattern_len + minimum_xauth_value_len + 1

section .bss
stat_buf resb 18
envp resq 3

section .text

%define counter r8
%define env_xauth r13
%define exec_path r12
%define xauth_len r9

global _start
_start:
        pop exec_path
        pop exec_path
        pop exec_path

        jmp set_xauth

        .continue:
        call verify_file

        call fork_process
        cmp rax, 0
        jl die
        jg exit

        call create_session
        call change_directory
        call close_file_descriptors

        .loop:
                call sleep

                call fork_process
                cmp rax, 0
                jl die
                jg .loop

                call start_program
                call die

set_xauth:
        .o_loop:
        pop env_xauth
        mov counter, 0

        test env_xauth, env_xauth
        jz .o_loop

        .i_loop:
        mov al, [xauth_pattern + counter]
        mov bl, [env_xauth + counter]

        cmp al, bl
        jnz .o_loop

        inc counter
        cmp counter, xauth_pattern_len
        je .get_value_length

        jmp .i_loop

        .get_value_length:
        mov counter, minimum_xauth_value_len
        mov xauth_len, minimum_xauth_len

        .loop:
        mov al, [env_xauth + counter]
        mov bl, BYTE "/"

        cmp al, bl
        jz _start.continue

        inc counter
        inc xauth_len

        jmp .loop

verify_file:
        prologue 16

        mov rax, syscall_stat
        mov rdi, exec_path
        mov rsi, stat_buf
        syscall

        cmp rax, 0
        jnz die

        epilogue 16

fork_process:
        prologue 16

        mov rax, syscall_fork
        syscall
        
        epilogue 16

create_session:
        prologue 16

        mov rax, syscall_setsid
        syscall

        cmp rax, -1
        jz die

        epilogue 16
        
change_directory:
        prologue 16

        mov rax, syscall_chdir
        lea rdi, root_dir
        syscall

        cmp rax, -1
        jz die

        epilogue 16

close_file_descriptors:
        prologue 16

        %macro close_file_descriptor 1
                mov rax, syscall_close
                mov rdi, %1
                syscall
                
                cmp rax, -1
                jz die
        %endmacro

        close_file_descriptor stdin
        close_file_descriptor stdout
        close_file_descriptor stderr
        
        epilogue 16

sleep:
        prologue 16

        mov QWORD [rsp], seconds_to_sleep
        mov QWORD [rsp + 8], 0

        mov rax, syscall_nanosleep
        lea rdi, [rsp]
        mov rsi, 0
        syscall

        epilogue 16

start_program:
        prologue 16

        mov QWORD [rel envp], env_xauth
        mov QWORD [rel envp + 8], env_display

        mov rax, syscall_execve
        mov rdi, exec_path
        mov rsi, 0
        mov rdx, envp
        syscall
        
        epilogue 16

die:
        exit_program 1

exit:
        exit_program 0

%undef counter
%undef env_xauth
%undef exec_path
%undef xauth_len

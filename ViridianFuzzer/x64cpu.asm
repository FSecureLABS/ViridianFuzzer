;
; Description: ...
;

.CODE 

PUBLIC VIFU_Hypercall

; 
; Hypercall wrapper
;
; Inputs:
; RCX = Input PCPU_REG_64
; RDX = Output PCPU_REG_64
;
; Outputs:
; RAX = HV_STATUS from vmcall
;
VIFU_Hypercall PROC

    push rsi
    push rdi
    push rdx                                ; Store output PCPU_REG_64

    mov rsi, rcx

    ;
    ; Hypercall inputs
    ; RCX = Hypercall input value
    ; RDX = Input param GPA
    ; R8  = Output param GPA 
    ;
    mov rcx, qword ptr [rsi+10h]
    mov rdx, qword ptr [rsi+18h]
    mov r8,  qword ptr [rsi+30h]

    ;
    ; Fastcall check
    ;
    mov     rax, rcx
    and     ax,  1  
    movzx   eax, ax  
    cmp     eax, 1 
    jz EXT_HYPERCALL_XMM_SETUP

    mov rax, qword ptr [rsi+00h]
    mov rbx, qword ptr [rsi+08h]
    mov rdi, qword ptr [rsi+28h]
    mov r9,  qword ptr [rsi+38h]
    mov r10, qword ptr [rsi+40h]
    mov r11, qword ptr [rsi+48h]
    jmp MAKE_VMCALL

    ;
    ; Extended fast hypercall (set it regardless)
    ;
    EXT_HYPERCALL_XMM_SETUP:
    movq xmm0, qword ptr [rsi+50h]
    movq xmm1, qword ptr [rsi+60h]
    movq xmm2, qword ptr [rsi+70h]
    movq xmm3, qword ptr [rsi+80h]
    movq xmm4, qword ptr [rsi+90h]
    movq xmm5, qword ptr [rsi+0a0h]

    MAKE_VMCALL:
    ;int 3
    vmcall

    ;
    ; Move any output data to PCPU_REG_64
    ;
    pop rsi                                 ; RSI now contains output PCPU_REG_64
    mov qword ptr [rsi+00h], rax
    mov qword ptr [rsi+08h], rbx
    mov qword ptr [rsi+10h], rcx
    mov qword ptr [rsi+18h], rdx
    mov qword ptr [rsi+28h], rdi
    mov qword ptr [rsi+30h], r8
    mov qword ptr [rsi+38h], r9
    mov qword ptr [rsi+40h], r10
    mov qword ptr [rsi+48h], r11
    ;mov qword ptr [rsi+20h], rsi

    pop rdi
    pop rsi
    ;
    ; RAX from vmcall is return code for our subroutine too
    ;
    ret
VIFU_Hypercall ENDP

END

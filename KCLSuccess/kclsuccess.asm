bits 64
org 0

%define KCL_VEH_MAGIC 0xDEADBEEFC0DEFACE

; key_struct:
; dq <key>
; dq <fake1>
; dq <fake2>
; dq <fake3>
; dq <fake4>

; ===============================================
; Блок 0
; rcx = struct key_struct
start:
	lea rbx, [rel start]
	push rcx
	mov r11, rcx
	mov rcx, [rel blocks]
	cmp qword [r11], rcx
	jne .next ; Фейковое условие, всегда выполняется
	mov rdx, rbx
	call KCLRSK
.next:
	mov rcx, [rel block1.addr]
	add rcx, rbx
    mov rdx, [rel block1.size]
    xor r8, r8
	xor r9, r9
	call decrypt
	lea rcx, [rel decrypt]
	push rcx
	lea rdx, [rel blocks]
	lea r8, [rel blocks_end]
	sub r8, rdx
	mov rax, [rel block1.addr]
	add rax, rbx
	push rax
	lea rdi, [rel start]
	lea rcx, [rel .call_point]
	sub rcx, rdi
	xor al, al
	cld
.call_point:
	rep stosb
	pop rax
	pop rcx
	pop r9
	mov r8, rbx
	call rax
cleanup:
	lea rdi, [rel start]
	mov rax, [rel blocks_end]
	add rax, rdi
	mov rcx, rdi
	add rcx, [rax]
	add rax, 8
	add rcx, [rax]
	sub rcx, rdi
	xor al, al
	cld
	jmp exit_func
	
; rcx = void*  decrypt_addr
; rdx = size_t decrypt_size
; r8  = void*  erase_addr
; r9  = size_t erase_size
; r11 = struct key_struct
decrypt:
	pop rax
	push r10
	mov r10, rax
	or rcx, rdx
	jz .erase
	push rcx
	push rdx
	xor rax, rax
	mov ecx, 5
.key:
	mov rbx, [r11]
	xor rax, rbx
	mov rdi, rbx
	not rdi
	add rdi, rax
	rol rdi, 3
	mov [r11], rdi
	add r11, 8
	loop .key
	push rax
	or r8, r9
	jz .no_erase
.erase:
	mov rcx, r9
	mov rdi, r8
	xor al, al
	cld
	rep stosb
	or rcx, rdx
	jz .no_decrypt
.no_erase:
	pop rax
	lea rcx, [rel KCLRSK]
	mov rdx, rax
	sub rsp, 32
	call KCLFillRawSecKey
	lea rcx, [rel KCLRSK]
	lea rdx, [rel KCLSK]
	call KCLGetSecKey
	lea r8, [rel KCLSK]
	add rsp, 32
	pop rdx
	pop rcx
	mov r9, rcx
	sub rsp, 32
	call KCLDecryptUA
	add rsp, 32
.no_decrypt:
	mov rax, r10
	pop r10
	jmp rax

; rcx = LPKCLRSK buff
; rdx = size_t   key
KCLFillRawSecKey:
	mov qword [rel KCLRawSecKeyArgs], rcx
	mov qword [rel KCLRawSecKeyArgs + 8], rdx
	mov byte [rel KCLRawSecKeyArgs + 16], 0
	mov rcx, [rel blocks]
	mov rdx, 2
	lea r8, [rel KCLRawSecKeyArgs]
	mov r9, 24
	jmp KCLStdCall

; rcx = LPKCLRSK input
; rdx = LPKCLSK  output
KCLGetSecKey:
	mov qword [rel KCLSecKeyArgs], rcx
	mov qword [rel KCLSecKeyArgs + 8], rdx
	mov byte [rel KCLSecKeyArgs + 16], 0
	mov rcx, [rel blocks]
	mov rdx, 1
	lea r8, [rel KCLSecKeyArgs]
	mov r9, 24
	jmp KCLStdCall
	
; rcx = void*   input
; rdx = size_t  len
; r8  = LPKCLSK key
; r9  = void*   output
KCLDecryptUA:
	mov qword [rel KCLCryptArgs], rcx
	mov qword [rel KCLCryptArgs + 8], rdx
	mov qword [rel KCLCryptArgs + 16], r8
	mov qword [rel KCLCryptArgs + 24], r9
	mov byte [rel KCLCryptArgs + 32], 0
	mov rcx, [rel blocks]
	mov rdx, 4
	lea r8, [rel KCLCryptArgs]
	mov r9, 40
	jmp KCLStdCall

; rcx = size_t magic
; rdx = size_t funcId
; r8  = void*  args
; r9  = size_t size
KCLStdCall:
	ud2
	ret

; rcx = void* blocks
; rdx = void* start
align 8
KCLRSK:
	mov r11, rdx
	mov r12, rcx
	call KCLSK
	call KCLSK3
	call KCLSecKeyArgs
	mov rcx, r11
	call KCLSK2
	mov rcx, -1
	push 0
	mov rdx, rsp
	xor r8, r8
	mov rax, [r12+56]
	mov r9, [rax]
	add r9, [rax+8]
	sub r9, [r12+8]
	mov r10, 0x18
	push 0x40
	push 0x3000
	sub rsp, 32
	call KCLRawSecKeyArgs
	add rsp, 48
	pop r13
	jmp KCLCryptArgs

; rcx = void* blocks
; rdx = void* start
align 8
KCLSK:
	mov r8, rcx
	mov r9, rdx
	mov rcx, rdx
	call check_symbol
	or rax, rax
	jnz cleanup
	xor rdx, rdx
.loop:
	add rdx, 8
	cmp rdx, 56
	je .next
	mov rcx, [r8+rdx]
	add rcx, r9
	call check_symbol
	or rax, rax
	jnz cleanup
	add rdx, 8                   
	jmp .loop
.next:
	mov r8, [r8+24]
	add r8, r9
	mov rcx, 4
.loop2:
	push rcx
	mov r10, rcx
	dec r10
	mov rcx, [r8 + r10*8]
	add rcx, r9
	call check_symbol
	or rax, rax
	jnz cleanup
	pop rcx
	loop .loop2
	ret
	
; rcx = char symbol
check_symbol:
	cmp byte [rcx], 0xE9
	je .changed
	cmp byte [rcx], 0xCC
	je .changed
	xor rax, rax
	ret
.changed:
	mov rax, 1
	ret

; rcx = void* base
KCLSK2:
	mov rdx, rcx
	push rbp
	mov rbp, rsp
	sub rsp, 128
	movdqu xmm0, [rcx]
	pxor xmm1, xmm1
	aeskeygenassist xmm2, xmm0, 0x01
	pshufd xmm2, xmm2, 0xFF
	pxor xmm0, xmm2
	movdqa [rsp], xmm0
	aeskeygenassist xmm2, xmm0, 0x02
	pshufd xmm2, xmm2, 0xFF
	pxor xmm0, xmm2
	movdqa [rsp+16], xmm0
	mov rcx, 1000
	mov rsi, [rel block1.addr]
	add rsi, rdx
.fake_aes_loop:
	movdqu xmm3, [rsi]
	pxor xmm3, xmm1
	aesenc xmm3, [rsp]
	aesenc xmm3, [rsp+16]
	aesenclast xmm3, xmm0
	movdqu [rsi], xmm3
	movdqa xmm1, xmm3
	add rsi, 16
	loop .fake_aes_loop
	mov rsp, rbp
	pop rbp
	ret
	
KCLSK3:
	mov rax, qword gs:[0x60]
	mov eax, dword [rax+0xBC]
	and eax, 0x70
	test eax, eax
	jnz cleanup
	ret

; 277 bytes

; rcx = void* arg1
; rdx = void* arg2
; r8  = void* arg3
; r9  = void* arg4
; r10 = DWORD syscall
align 8
KCLRawSecKeyArgs:
	mov eax, r10d
	mov r10, rcx
	call .get_rip
.get_rip:
	pop rbx
	add rbx, 10
	jmp rbx
	nop
	nop
	syscall
	ret
	times (24 - ($ - KCLRawSecKeyArgs)) db 0xCC ; 1 byte

align 8
KCLSecKeyArgs:
	mov rbx, 0x7FFE0000
	mov eax, dword [rbx+0x320]
	cmp eax, 0x10000
	jb cleanup
	ret
	times (24 - ($ - KCLSecKeyArgs)) db 0xCC ; 1 byte

; r11 = void* start
; r12 = void* blocks
; r13 = void* newbase
align 8
KCLCryptArgs:
	mov rsi, [r12+8]
	add rsi, r11
	mov rdi, r13
	mov rax, [r12+56]
	mov rcx, [rax]
	add rcx, [rax+8]
	mov r9, rcx
	sub rcx, rsi
	rep movsb
	mov r8, r11
	xor rcx, rcx
	xor rdx, rdx
	xor r11, r11
	push r13
	jmp decrypt

; 72 bytes

; Структура для билдера
align 8
blocks: dq KCL_VEH_MAGIC ; Как метка и magic для KCL
block1:
.addr: dq block1_func - start
.size: dq block1_func_end - block1_func
block2:
.addr: dq block2_func - start
.size: dq block2_func_end - block2_func
block3:
.addr: dq block3_func - start
.size: dq block3_func_end - block2_func
blocks_end: dq block3 - start ; Указатель на последний блок

; =============================================
; Блок 1
; rcx = void*  decrypt_func
; rdx = void*  blocks_addr
; r8  = void*  base
; r9  = struct key_struct
align 16
block1_func:
	pop r10
	mov r12, rcx
	mov r13, rdx
	mov r14, r8
	mov r15, r9
	mov rcx, [r13+24]
	add rcx, r14
	mov rdx, [r13+32]
	xor r8, r8
	xor r9, r9
	mov r11, r15
	call r12
	mov rcx, [r13+40]
	add rcx, r14
	mov rdx, [r13+48]
	xor r8, r8
	xor r9, r9
	mov r11, r15
	call r12
	mov r8, [r13+8]
	add r8, r14
	mov r9, [r13+16]
	xor rcx, rcx
	xor rdx, rdx
	xor r11, r11
	push r10
	mov rax, [r13+40]
	add rax, r14
	push rax
	cmp r10, r14
	jbe .fake_check
	jmp r12
	ret
.fake_check:
	call r12
	jmp cleanup
	nop
	
block1_func_end: dq 0

; =============================================
; Блок 2
align 16
block2_func:
block2_map:
.xor_decrypt_addr: dq xor_decrypt - start
.KCLRuntimeHashDJB2_addr: dq KCLRuntimeHashDJB2 - start
.KCLRuntimeHashDJB2_W_addr: dq KCLRuntimeHashDJB2_W - start
.GetFuncFromModule_addr: dq GetFuncFromModule - start

%macro KCLHashStringDJB2 2
    %assign %%hash 5381
    %strlen %%len %2
    %assign %%i 1
    %rep %%len
        %substr %%c %2 %%i
        %assign %%hash ((%%hash * 33) + %%c) & 0xFFFFFFFF 
        %assign %%i %%i + 1
    %endrep
    %define %1 %%hash
%endmacro

%macro KCLHashStringDJB2_W 2
    %assign %%hash 5381
    %strlen %%len %2
    %assign %%i 1
    %rep %%len
        %substr %%c %2 %%i
        %if %%c >= 'A' && %%c <= 'Z'
            %assign %%c %%c + 32
        %endif
        %assign %%hash ((%%hash * 33) + %%c) & 0xFFFFFFFF
        %assign %%i %%i + 1
    %endrep
    %define %1 %%hash
%endmacro

%macro XOR_STRING 2
    %strlen %%len %1
    %assign %%i 1
    %rep %%len
        %substr %%c %1 %%i
        db %%c ^ %2
        %assign %%i %%i + 1
    %endrep
    db 0 ^ %2                 
%endmacro

; rcx = char*  str
; rdx = size_t len
; r8  = char   key
; return = char*
xor_decrypt:
	mov rax, rcx
	dec rdx
	jz .set_null
.loop:
	xor byte [rcx], r8b
	inc rcx
	dec rdx
	jnz .loop
	
.set_null:
	mov byte [rcx], 0
	ret

; rcx    = const char* str
; return = DWORD
KCLRuntimeHashDJB2:
	mov eax, 5381
	mov r8, rcx
.loop:
	movzx ecx, byte [r8]
	test ecx, ecx
	jz .ret
	mov edx, eax
	shl edx, 5
	add edx, eax
	add edx, ecx
	mov eax, edx
	inc r8
	jmp .loop
.ret:
	ret
	
; rcx    = const wchar_t* str
; return = DWORD
KCLRuntimeHashDJB2_W:
	mov eax, 5381
	mov r8, rcx
.loop:
	movzx ecx, word [r8]
	test ecx, ecx
	jz .ret
	lea r9d, [ecx - "A"]
	cmp r9d, "Z"-"A"
	ja .next
	add ecx, 32
.next:
	mov edx, eax
	shl edx, 5
	add edx, eax
	add edx, ecx
	mov eax, edx
	add r8, 2
	jmp .loop
.ret:
	ret
	
; rcx    = DWORD hash
; return = PVOID
GetModuleBaseByHash:
	mov rax, rcx
	mov rdx, qword gs:[0x60]
	mov rdx, [rdx+0x18]
	mov r8, rdx
	add r8, 0x10
	mov rdx, [r8]
.loop:
	cmp r8, rdx
	je .ret
	mov r9, [rdx+0x60]
	or r9, r9
	jz .next
	push rax
	push r8
	push rdx
	mov rcx, r9
	call KCLRuntimeHashDJB2_W
	pop rdx
	pop r8
	pop rcx
	cmp rax, rcx
	jne .next
	mov rax, [rdx+0x30]
	ret
.next:
	mov rdx, [rdx]
	jmp .loop
.ret:
	xor rax, rax
	ret
	
; rcx    = PVOID base
; rdx    = DWORD hash
; return = PVOID
GetProcAddressByHash:
	push r10
	push r11
	push r12
	cmp word [rcx], 0x5A4D
	jne .nullret
	mov r8d, dword [rcx+0x3C]
	add r8, rcx
	cmp dword [r8], 0x00004550
	jne .nullret
	add r8, 0x88
	mov r8d, dword [r8]
	cmp r8, 0
	jz .nullret
	add r8, rcx
	mov r9d, dword [r8+0x20]
	add r9, rcx
	mov r10d, dword [r8+0x18]
	mov r11d, dword [r8+0x1C]
	add r11, rcx
	mov r12d, dword[r8+0x24]
	add r12, rcx
	xor rax, rax
.loop:
	cmp rax, r10
	jae .nullret
	mov r8d, dword [r9+rax*4]
	add r8, rcx
	push rax
	push rdx
	push rcx
	mov rcx, r8
	call KCLRuntimeHashDJB2
	mov r8, rax
	pop rcx
	pop rdx
	pop rax
	cmp r8, rdx
	jne .next
	movzx r8, word [r12+rax*2]
	mov eax, [r11+r8*4]
	add rax, rcx
	pop r12
	pop r11
	pop r10
	ret
.next:
	inc rax
	jmp .loop
.nullret:
	xor rax, rax
	pop r12
	pop r11
	pop r10
	ret

; rcx    = DWORD module
; rdx    = DWORD hash
; return = PVOID
GetFuncFromModule:
	push rdx
	call GetModuleBaseByHash
	or rax, rax
	jnz .next
	pop rdx
	xor rax, rax
	ret
.next:
	mov rcx, rax
	pop rdx
	jmp GetProcAddressByHash

block2_func_end: dq 0

; =============================================
; Блок 3
; r12 = void*  decrypt_func
; r13 = void*  blocks_addr
; r14 = void*  base
; r15 = struct key_struct

KCLHashStringDJB2_W HASH_KERNEL32,     "kernel32.dll"
KCLHashStringDJB2   HASH_GETSTDHANDLE, "GetStdHandle"
KCLHashStringDJB2   HASH_WRITECONSOLE, "WriteConsoleA"

message: XOR_STRING "YOU WIN! #KCL", 0x67

align 16
block3_func:
	mov r15, [r13+24]
	add r15, r14
	mov rcx, HASH_KERNEL32
	mov rdx, HASH_GETSTDHANDLE
	mov rax, [r15+24]
	add rax, r14
	sub rsp, 32
	call rax
	add rsp, 32
	mov r12, rax
	mov rcx, HASH_KERNEL32
	mov rdx, HASH_WRITECONSOLE
	mov rax, [r15+24]
	add rax, r14
	sub rsp, 32
	call rax
	add rsp, 32
	mov r13, rax
	mov rcx, -11
	sub rsp, 32
	call r12
	add rsp, 32
	mov rbx, rax
	lea rcx, [rel message]
	mov rdx, 14
	mov r8, 0x67
	mov rax, [r15+0]
	add rax, r14
	call rax
	mov rcx, rbx
	mov rdx, rax
	mov r8, 13
	xor r9, r9
	sub rsp, 40
	mov qword [rsp+32], 0
	call r13
	add rsp, 40
	ret
	
	
block3_func_end: dq 0
	
; ===============================================
align 16
exit_func:
	rep stosb
	mov ecx, 0xC0000100
	xor rax, rax
	xor rdx, rdx
	wrmsr
	xor rax, rax
	ret
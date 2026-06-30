.code

; extern "C" void KCLStdCall(size_t magic, size_t funcId, void* pArgs, size_t size);
KCLStdCall proc
    ud2    ; Инициируем краш (ILLEGAL_INSTRUCTION)
    ret    ; Сюда вернется выполнение после того, как VEH сдвинет RIP
KCLStdCall endp

end
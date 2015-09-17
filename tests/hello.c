void main() {
__asm__(
"         jmp forward\n"
"backward:\n"
"         pop   %rsi\n"
"         mov   $4, %rax\n"
"         mov   $2, %rdi\n"
"         mov   %rsi, %rcx\n"
"         mov   $12, %rdx\n"
"         int   $0x80\n"
"         int3\n"
"forward:\n"
"         call backward\n"
"         .string \"Hello World\\n\"");
}

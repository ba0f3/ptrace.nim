import posix, ptrace, ptrace/syscall


var child: Pid
var orig_eax, eax: clong
var params: array[3, clong]
var status: cint
var insyscall = 0


child = fork()

if child == 0:
  traceMe()
  discard execl("/bin/ls", "ls")
else:
  while true:
    wait(addr status)
    if WIFEXITED(status):
      break
    orig_eax = peekUser(child, ORIG_RAX)
    if orig_eax == SYS_write:
      if insyscall == 0:
        insyscall = 1
        params[0] = peekUser(child, SYSCALL_ARG1)
        params[1] = peekUser(child, SYSCALL_ARG2)
        params[2] = peekUser(child, SYSCALL_ARG3)
        echo "Write called with ", params[0], ", ", params[1], ", ", params[2]

        var regs: Registers
        getRegs(child, addr regs)
        echo regs.rdi, " ", regs.rsi, " ", regs.rdx

      else:
        eax = peekUser(child, RAX)
        echo "Write returned with ", eax
        insyscall = 0

    discard ptrace(PTRACE_SYSCALL, child, 0, 0)

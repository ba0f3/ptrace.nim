import posix
import ../ptrace/ptrace
import ../ptrace/syscall


var child: Pid
var orig_eax, eax: clong
var params: array[3, clong]
var status: cint
var insyscall = 0


child = fork()

if child == 0:
  discard traceMe()
  discard execl("/bin/ls", "ls")
else:
  while true:
    discard wait(status)
    if WIFEXITED(status):
      break
    orig_eax = peekUser(child, ORIG_RAX)
    if orig_eax == SYS_write:
      if insyscall == 0:
        insyscall = 1
        params[0] = peekUser(child, RBX)
        params[1] = peekUser(child, RCX)
        params[2] = peekUser(child, RDX)
        echo "Write called with ", params[0], ", ", params[1], ", ", params[2]

        let regs: Registers = getRegs(child)
        echo regs.rbx, " ", regs.rcx, " ", regs.rdx

      else:
        eax = peekUser(child, RAX)
        echo "Write returned with ", eax
        insyscall = 0

    discard ptrace(PTRACE_SYSCALL, child, 0, 0)

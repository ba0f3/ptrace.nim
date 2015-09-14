import posix
import ../ptrace/ptrace
import ../ptrace/syscall

var child: Pid
var orig_eax, eax: clong
var params: array[3, clong]
var status: cint
var insyscall = 0
var str: cstring

child = fork()

if child == 0:
  discard traceme()
  discard execl("/bin/ls", "ls")
else:
  while true:
    discard wait(status)
    if WIFEXITED(status):
      break
    orig_eax = ptrace(PTRACE_PEEKUSER, child, ORIG_RAX, nil)
    if orig_eax == SYS_write:
      if insyscall == 0:
        insyscall = 1
        params[0] = ptrace(PTRACE_PEEKUSER, child, RBX, nil)
        params[1] = ptrace(PTRACE_PEEKUSER, child, RCX, nil)
        params[2] = ptrace(PTRACE_PEEKUSER, child, RDX, nil)
        echo "Write called with ", params[0], ", ", params[1], ", ", params[2]

        let regs: Registers = getRegs(child)
        echo regs.rbx, " ", regs.rcx, " ", regs.rdx
        str = getString(child, params[1], params[2])
        echo str

      else:
        eax = ptrace(PTRACE_PEEKUSER, child, RAX, nil)
        echo "Write returned with ", eax
        insyscall = 0

    discard ptrace(PTRACE_SYSCALL, child, 0, nil)

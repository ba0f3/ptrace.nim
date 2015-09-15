import posix
import strutils
import ../ptrace/ptrace
import ../ptrace/syscall

proc c_printf(frmt: cstring) {.importc: "printf", header: "<stdio.h>", varargs.}

var child: Pid

child = fork()
if child == 0:
  traceMe()
  #discard execl("./dummy1", "dummy1")
  discard execl("/bin/ls", "ls")
else:
  var status: cint
  var regs: Registers
  var start = 0
  var ins: clong

  while true:
    discard wait(status)

    if WIFEXITED(status):
      break

    regs = getRegs(child)
    if start == 1:
      ins = getData(child, regs.rip.clong)
      c_printf("RIP: %lx Instruction executed: %lx\n", regs.rip, ins)
    if regs.orig_rax == SYS_write.culong:
      start = 1
      singleStep(child)
    else:
      syscall(child)

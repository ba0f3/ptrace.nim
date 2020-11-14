import posix, ptrace, private/syscall

proc c_printf(frmt: cstring) {.importc: "printf", header: "<stdio.h>", varargs.}

var child: Pid

child = fork()
if child == 0:
  traceMe()
  echo execl("/bin/ls", "-la")
  if errno != 0:
    echo strerror(errno)
else:
  var status: cint
  var regs: Registers
  var start = 0
  var ins: clong

  while true:
    wait(addr status)
    echo status
    if WIFEXITED(status):
      break

    getRegs(child, addr regs)
    if start == 1:
      ins = getData(child, regs.rip.clong)
      c_printf("RIP: %lx Instruction executed: %lx\n", regs.rip, ins)
    if regs.orig_rax == SYS_write.culong:
      start = 1
      singleStep(child)
    else:
      syscall(child)

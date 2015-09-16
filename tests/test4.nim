import os
import posix
import strutils
import ../ptrace/ptrace
import ../ptrace/syscall

proc c_printf(frmt: cstring) {.importc: "printf", header: "<stdio.h>", varargs.}

var traced: Pid
var regs: Registers
var ins: clong
var status: cint
var data: CValue
var toggle = false

echo sizeof(cint)

if paramCount() != 1:
  quit("Usage: $# <pid>" % [paramStr(0)])
echo "Tracing process: ", paramStr(1)

traced = parseInt(paramStr(1))
attach(traced)
if errno != 0:
  quit($strerror(errno), errno.int)

while true:
  discard wait(addr status)
  if WIFEXITED(status):
    break

  if toggle:
    toggle = false
    regs = getRegs(traced)
    ins = getData(traced, regs.rip.clong)
    c_printf("RIP: %lx Instruction executed: %lx\n", regs.rip, ins)
    var address = regs.rsi
    if regs.orig_rax == SYS_write.culong:
      echo getString(traced, address.clong, regs.rdx.int)
    else:
      echo regs.orig_rax
  else:
    toggle = true

  syscall(traced)

detach(traced, 0)

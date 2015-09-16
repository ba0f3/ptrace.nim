import strutils, os, posix

import ../ptrace/ptrace
import ../ptrace/syscall

proc getchar(): cint {.importc.}

var
  tracee: Pid
  regs: Registers
  le = 41
  code = [0xeb, 0x15, 0x5e, 0xb8, 0x04, 0x00, 0x00, 0x00, 0xbb, 0x02, 0x00, 0x00, 0x00, 0x89, 0xf1, 0xba, 0x0c, 0x00, 0x00, 0x00, 0xcd, 0x80, 0xcc, 0xe8, 0xe6, 0xff, 0xff, 0xff, 0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x57, 0x6f, 0x72, 0x6c, 0x64, 0x0a, 0x00]
  backup: array[41 , char]


if paramCount() != 1:
  quit("Usage: $# <pid>" % [paramStr(0)])

echo "Tracing process: ", paramStr(1)

tracee = parseInt(paramStr(1))


attach(tracee)
if errno != 0:
  quit($strerror(errno))
wait(nil)

regs = getRegs(tracee)

getData(tracee, regs.rip.clong, backup, le)
putData(tracee, regs.rip.clong, code, le)

setRegs(tracee, addr regs)

cont(tracee)
wait(nil)

echo "The process stopped, putting back the original instructions"
echo "Press <enter> to continue"
discard getchar()

putData(tracee, regs.rip.clong, backup, le)
if errno != 0:
  echo strerror(errno)
setRegs(tracee, addr regs)
if errno != 0:
  echo strerror(errno)

echo "Letting it continue with original flow"

detach(tracee)

import strutils, os, posix, hex

import ../ptrace/ptrace
import ../ptrace/syscall

const
    le = 32

var
  tracee: Pid
  oldregs, regs: Registers
#  code = [0xe8, 0x0d, 0x00, 0x00, 0x00, 0x48, 0x65, 0x6c,
#          0x6c, 0x6f, 0x20, 0x57, 0x6f, 0x72, 0x6c, 0x64,
#          0x0a, 0x00, 0x5e, 0x48, 0xc7, 0xc0, 0x04, 0x00,
#          0x00, 0x00, 0x48, 0xc7, 0xc7, 0x02, 0x00, 0x00,
#          0x00, 0x48, 0x89, 0xf1, 0x48, 0xc7, 0xc2, 0x0c,
#          0x00, 0x00, 0x00, 0xcd, 0x80, 0xcc, 0x90, 0x5d]

  code = [0xeb, 0x1c, 0x5e, 0x48, 0xc7, 0xc0, 0x04, 0x00,
          0x00, 0x00, 0x48, 0xc7, 0xc7, 0x02, 0x00, 0x00,
          0x00, 0x48, 0x89, 0xf1, 0x48, 0xc7, 0xc2, 0x0c,
          0x00, 0x00, 0x00, 0xcd, 0x80, 0xcc, 0xe8, 0xdf]
  backup: array[le , char]


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

#setRegs(tracee, addr regs)
cont(tracee)

wait(nil)

echo "The process stopped, putting back the original instructions"

putData(tracee, regs.rip.clong, backup, le)
if errno != 0:
  echo strerror(errno)
setRegs(tracee, addr regs)
if errno != 0:
  echo strerror(errno)

echo "Letting it continue with original flow"

detach(tracee)

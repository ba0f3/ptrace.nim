import strutils, os, posix

import ../ptrace/ptrace
import ../ptrace/syscall
import ../ptrace/utils


const
  LENGTH = 41

var
  tracee: Pid
  oldregs, regs: Registers
  address: clong

  code = [0xeb, 0x15, 0x5e, 0xb8, 0x04, 0x00,
          0x00, 0x00, 0xbb, 0x02, 0x00, 0x00, 0x00, 0x89, 0xf1, 0xba,
          0x0c, 0x00, 0x00, 0x00, 0xcd, 0x80, 0xcc, 0xe8, 0xe6, 0xff,
          0xff, 0xff, 0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x57, 0x6f,
          0x72, 0x6c, 0x64, 0x0a, 0x00]
  backup: array[LENGTH, char]


if paramCount() != 1:
  quit("Usage: $# <pid>" % [paramStr(0)])

echo "Tracing process: ", paramStr(1)

tracee = parseInt(paramStr(1))


attach(tracee)
if errno != 0:
  quit($strerror(errno))
wait(nil)

getRegs(tracee, addr regs)

address = freeSpaceAddr(tracee).clong

echo "Free space address: ", address

getData(tracee, address, backup, LENGTH)
putData(tracee, address, code, LENGTH)

for x in backup:
  echo x.ord

copyMem(addr oldregs, addr regs, sizeof(regs))
regs.eip = address
regs.eax = SYS_write

echo regs
echo oldregs

setRegs(tracee, addr regs)
if errno != 0:
  echo "regs ", strerror(errno)

cont(tracee)
wait(nil)

echo "The process stopped, putting back the original instructions"

putData(tracee, address, backup, LENGTH)
if errno != 0:
  echo "put ", errno, " ", strerror(errno)
setRegs(tracee, addr oldregs)
if errno != 0:
  echo "regs ", errno, " ", strerror(errno)
detach(tracee)

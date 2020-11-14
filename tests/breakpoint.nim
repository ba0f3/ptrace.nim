import strutils, os, posix, ptrace, ptrace/syscall

proc getchar(): cint {.importc.}

var
  tracee: Pid
  regs: Registers
  code: array[WORD_SIZE, char]
  backup: array[WORD_SIZE, char]


if paramCount() != 1:
  quit("Usage: $# <pid>" % [paramStr(0)])

echo "Tracing process: ", paramStr(1)

tracee = parseInt(paramStr(1)).Pid


attach(tracee)
if errno != 0:
  quit($strerror(errno))
wait(nil)

getRegs(tracee, addr regs)

getData(tracee, regs.rip.clong, backup, WORD_SIZE)
code = backup
code[0] = 0xcd.char
code[1] = 0x80.char
code[2] = 0xcc.char
putData(tracee, regs.rip.clong, code, WORD_SIZE)

cont(tracee)
wait(nil)

echo "The process stopped, putting back the original instructions"
echo "Press <enter> to continue"
discard getchar()


putData(tracee, regs.rip.clong, backup, WORD_SIZE)
if errno != 0:
  echo strerror(errno)
setRegs(tracee, addr regs)
if errno != 0:
  echo strerror(errno)
detach(tracee)

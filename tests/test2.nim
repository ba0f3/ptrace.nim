import posix
import unicode
import ../ptrace/ptrace
import ../ptrace/syscall

var child: Pid
var syscallNo: clong
var params: array[3, clong]
var status: cint
var toggle = false

child = fork()

if child == 0:
  discard traceme()
  discard execl("/bin/ls", "ls", nil)
else:
  while true:
    discard wait(status)
    if WIFEXITED(status):
      break
    syscallNo = peekUser(child, SYSCALL_NUM)
    if syscallNo == SYS_write:
      if not toggle:
        toggle = true
        params[0] = peekUser(child, SYSCALL_ARG1)
        params[1] = peekUser(child, SYSCALL_ARG2)
        params[2] = peekUser(child, SYSCALL_ARG3)
        var str = getString(child, params[1], params[2])
        str = reversed($str)
        putString(child, params[1], $str, params[2])
      else:
        toggle = false
    else:
      echo syscallNo

    discard ptrace(PTRACE_SYSCALL, child, 0, 0)

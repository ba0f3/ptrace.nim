import posix
import unicode
import ptrace, ptrace/syscall

var child: Pid
var syscallNo: clong
var params: array[3, clong]
var status: cint
var toggle = false

child = fork()

if child == 0:
  traceMe()
  discard execl("/bin/ls", "ls", nil)
  if errno != 0:
    echo "execl: ", strerror(errno)
else:
  while true:
    wait(addr status)
    if WIFEXITED(status):
      break
    syscallNo = peekUser(child, SYSCALL_NUM)
    if errno != 0:
      echo "peekUser: ", strerror(errno)
    if syscallNo == SYS_write:
      if not toggle:
        toggle = true
        params[0] = peekUser(child, SYSCALL_ARG1)
        params[1] = peekUser(child, SYSCALL_ARG2)
        params[2] = peekUser(child, SYSCALL_ARG3)
        #var str: string = newString(params[2])
        #getData(child, params[1], str, params[2])
        var str = getString(child, params[1], params[2])
        putString(child, params[1], reversed(str))
      else:
        toggle = false

    syscall(child)

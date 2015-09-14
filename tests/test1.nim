import posix
import ../ptrace


var child: Pid
var orig_eax, eax: clong
var params: array[3, clong]
var status: cint
var insyscall = 0;

child = fork()

if child == 0:
  discard traceme()
  execl("/bin/ls", "ls", nil)
else:
  while true:
    discard wait(status)
    orig_eax = ptrace(PTRACE_PEEKUSER, child, 4 * 15, nil)
    if orig_eax == 4:
      if insyscall == 0:
        insyscall = 1
        params[0] = ptrace(PTRACE_PEEKUSER, child, 4 * EBX, nil)


discard """


          if(orig_eax == SYS_write) {
             if(insyscall == 0) {
                /* Syscall entry */
                insyscall = 1;
                params[0] = ptrace(PTRACE_PEEKUSER,
                                   child, 4 * EBX,
                                   NULL);
                params[1] = ptrace(PTRACE_PEEKUSER,
                                   child, 4 * ECX,
                                   NULL);
                params[2] = ptrace(PTRACE_PEEKUSER,
                                   child, 4 * EDX,
                                   NULL);
                printf("Write called with "
                       "%ld, %ld, %ld\n",
                       params[0], params[1],
                       params[2]);
                }
          else { /* Syscall exit */
                eax = ptrace(PTRACE_PEEKUSER,
                             child, 4 * EAX, NULL);
                    printf("Write returned "
                           "with %ld\n", eax);
                    insyscall = 0;
                }
            }
            ptrace(PTRACE_SYSCALL,
                   child, NULL, NULL);
        }
    }
    return 0;
}
"""

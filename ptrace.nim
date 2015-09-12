import posix

type
  Registers* = object
    r15*: culong
    r14*: culong
    r13*: culong
    r12*: culong
    bp*: culong
    bx*: culong
    r11*: culong
    r10*: culong
    r9*: culong
    r8*: culong
    ax*: culong
    xc*: culong
    dx*: culong
    si*: culong
    di*: culong
    orig_ax*: culong
    ip*: culong
    flags*: culong
    sp*: culong
    ss*: culong
    fs_base*: culong
    gs_base*: culong
    ds*: culong
    es*: culong
    fs*: culong
    gs*: culong

const
  PTRACE_TRACEME* = 0
  PTRACE_PEEKTEXT* = 1
  PTRACE_PEEKDATA* = 2
  PTRACE_PEEKUSER* = 3
  PTRACE_POKETEXT* = 4
  PTRACE_POKEDATA* = 5
  PTRACE_POKEUSER* = 6
  PTRACE_CONT* = 7
  PTRACE_KILL* = 8
  PTRACE_SINGLESTEP* = 9
  PTRACE_GETREGS* = 12
  PTRACE_SETREGS* = 13
  PTRACE_GETFPREGS* = 14
  PTRACE_SETFPREGS* = 15
  PTRACE_ATTACH* = 16
  PTRACE_DETACH* = 17
  PTRACE_GETFPXREGS* = 18
  PTRACE_SETFPXREGS* = 19
  PTRACE_SYSCALL* = 24
  PTRACE_SETOPTIONS* = 0x4200
  PTRACE_GETEVENTMSG* = 0x4201
  PTRACE_GETSIGINFO* = 0x4202
  PTRACE_SETSIGINFO* = 0x4203
  PTRACE_SEIZE* = 0x4206
  PTRACE_INTERRUPT* = 0x4207
  PTRACE_LISTEN* = 0x4208

  PTRACE_EVENT_FORK* = 1
  PTRACE_EVENT_VFORK* = 2
  PTRACE_EVENT_CLONE* = 3
  PTRACE_EVENT_EXEC* = 4
  PTRACE_EVENT_VFORK_DONE* =  5
  PTRACE_EVENT_EXIT* = 6
  PTRACE_EVENT_SECCOMP* = 7
  PTRACE_EVENT_STOP* = 128


  PTRACE_O_TRACESYSGOOD* = 1
  PTRACE_O_TRACEFORK* = 1 shl PTRACE_EVENT_FORK
  PTRACE_O_TRACEVFORK* = 1 shl PTRACE_EVENT_VFORK
  PTRACE_O_TRACECLONE* = 1 shl PTRACE_EVENT_CLONE
  PTRACE_O_TRACEEXEC* = 1 shl PTRACE_EVENT_EXEC
  PTRACE_O_TRACEVFORKDONE* = 1 shl PTRACE_EVENT_VFORK_DONE
  PTRACE_O_TRACEEXIT* = 1 shl PTRACE_EVENT_EXIT
  PTRACE_O_TRACESECCOMP* = 1 shl PTRACE_EVENT_SECCOMP
  PTRACE_O_EXITKILL* = 1 shl 20
  PTRACE_O_MASK* = 0x000000ff or PTRACE_O_EXITKILL


{.pragma: c,
  importc,
  header: "sys/ptrace.h"
.}
proc ptrace*(request: cint, pid: Pid, a: ptr cint, data: pointer): clong {.c, inline.}

proc setOptions*(p: Pid, opts: ptr cint): clong =
  ptrace(PTRACE_SETOPTIONS, p, nil, opts)

proc getRegs*(p: int): Registers =
  discard ptrace(PTRACE_GETREGS, p, nil, addr result)

proc setRegs*(p: Pid, regs: ptr Registers): clong =
  ptrace(PTRACE_SETREGS, p, nil, regs)

proc attach*(p: Pid): clong =
  ptrace(PTRACE_ATTACH, p, nil, nil)

proc detach*(p: Pid, signal: ptr cint): clong =
  ptrace(PTRACE_DETACH, p, nil, signal)

proc cont*(p: Pid, signal: ptr cint): clong =
  ptrace(PTRACE_CONT, p, nil, signal)

proc traceme*(): clong =
  ptrace(PTRACE_TRACEME, 0, nil, nil)

when isMainModule:
  var child: Pid;
  var orig_ax: clong;

  child = fork()

  if child == 0:
    discard traceme()
    discard execl("/bin/ls", "ls", nil)

  else:
    var a: cint = 0
    echo wait(a)
    var data: cint = 8 * 15
    orig_ax = ptrace(PTRACE_PEEKUSER, child, addr data, nil)
    echo errno, " ", strerror(errno)
    echo "The child made a system call: ", orig_ax
    discard cont(child, addr data)

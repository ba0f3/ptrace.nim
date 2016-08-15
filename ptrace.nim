import posix

{.pragma: c,
 importc,
 header: "sys/ptrace.h"
.}

const
  WORD_SIZE* = sizeof(clong)

type
  CValue* = object {.union.}
    lg*: clong
    d*: cdouble
    f*: cfloat
    i*: cint
    ui*: cuint
    chars*: array[WORD_SIZE, cchar]

var
  PTRACE_TRACEME* {.c.}: cint
  PTRACE_PEEKTEXT* {.c.}: cint
  PTRACE_PEEKDATA* {.c.}: cint
  PTRACE_PEEKUSER* {.c.}: cint
  PTRACE_POKETEXT* {.c.}: cint
  PTRACE_POKEDATA* {.c.}: cint
  PTRACE_POKEUSER* {.c.}: cint
  PTRACE_CONT* {.c.}: cint
  PTRACE_KILL* {.c.}: cint
  PTRACE_SINGLESTEP* {.c.}: cint
  PTRACE_GETREGS* {.c.}: cint
  PTRACE_SETREGS* {.c.}: cint
  PTRACE_GETFPREGS* {.c.}: cint
  PTRACE_SETFPREGS* {.c.}: cint
  PTRACE_ATTACH* {.c.}: cint
  PTRACE_DETACH* {.c.}: cint
  PTRACE_GETFPXREGS* {.c.}: cint
  PTRACE_SETFPXREGS* {.c.}: cint
  PTRACE_SYSCALL* {.c.}: cint
  PTRACE_SETOPTIONS* {.c.}: cint
  PTRACE_GETEVENTMSG* {.c.}: cint
  PTRACE_GETSIGINFO* {.c.}: cint
  PTRACE_SETSIGINFO* {.c.}: cint
  PTRACE_SEIZE* {.c.}: cint
  PTRACE_INTERRUPT* {.c.}: cint
  PTRACE_LISTEN* {.c.}: cint

const
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

when hostCPU == "i386":
  type
    Registers* = object
      ebx*: clong
      ecx*: clong
      edx*: clong
      esi*: clong
      edi*: clong
      ebp*: clong
      eax*: clong
      xds*: clong
      xes*: clong
      xfs*: clong
      xgs*: clong
      origin_eax*: clong
      eip*: clong
      eflags*: clong
      esp*: clong
      xss*: clong
  const
    EBX* = 0
    ECX* = 1
    EDX* = 2
    ESI* = 3
    EDI* = 4
    EBP* = 5
    EAX* = 6
    DS* = 7
    ES* = 8
    FS* = 9
    GS* = 10
    ORIG_EAX* = 11
    EIP* = 12
    CS* = 13
    EFL* = 14
    UESP* = 15
    SS* =16
else:

  type
    Registers* = object
      r15*: culong
      r14*: culong
      r13*: culong
      r12*: culong
      rbp*: culong
      rbx*: culong
      r11*: culong
      r10*: culong
      r9*: culong
      r8*: culong
      rax*: culong
      rcx*: culong
      rdx*: culong
      rsi*: culong
      rdi*: culong
      orig_rax*: culong
      rip*: culong
      cs*: culong
      eflags*: culong
      rsp*: culong
      ss*: culong
      fs_base*: culong
      gs_base*: culong
      ds*: culong
      es*: culong
      fs*: culong
      gs*: culong

  const
    R15* = 0
    R14* = 8
    R13* = 16
    R12* = 24
    RBP* = 32
    RBX* = 40
    R11* = 48
    R10* = 56
    R9* = 64
    R8* = 72
    RAX* = 80
    RCX* = 88
    RDX* = 96
    RSI* = 104
    RDI* = 112
    ORIG_RAX* = 120
    RIP* = 128
    CS* = 136
    EFLAGS* = 144
    RSP* = 152
    SS* = 160
    FS_BASE* = 168
    GS_BASE* = 176
    DS* = 184
    ES* = 192
    FS* = 200
    GS* = 208

when hostCPU == "i386":
  const
    SYSCALL_NUM* = ORIG_EAX
    SYSCALL_ARG1* = EBX
    SYSCALL_ARG2* = ECX
    SYSCALL_ARG3* = EDX
    SYSCALL_RET_OFFSET* = EAX
else:
  const
    SYSCALL_NUM* = ORIG_RAX
    SYSCALL_ARG1* = RDI
    SYSCALL_ARG2* = RSI
    SYSCALL_ARG3* = RDX
    SYSCALL_RET_OFFSET* = RAX

proc ptrace*[T](request: cint, pid: Pid, a: clong, data: T): clong {.c, discardable.}

template setOptions*(p: Pid, opts: ptr cint) =
  ptrace(PTRACE_SETOPTIONS, p, 0, opts)

proc getRegs*(p: int): Registers {.inline.} =
  discard ptrace(PTRACE_GETREGS, p, 0, result)

template setRegs*(p: Pid, regs: ptr Registers) =
  ptrace(PTRACE_SETREGS, p, 0, regs)

template attach*(p: Pid) =
  ptrace(PTRACE_ATTACH, p, 0, 0)

template detach*(p: Pid, signal: clong = 0) =
  ptrace(PTRACE_DETACH, p, 0, signal)

template cont*(p: Pid, signal: clong = 0) =
  ptrace(PTRACE_CONT, p, 0, signal)

template traceMe*() =
  ptrace(PTRACE_TRACEME, 0, 0, 0)

template syscall*(p: Pid) =
  ptrace(PTRACE_SYSCALL, p, 0, 0)

template singleStep*(p: Pid) =
  ptrace(PTRACE_SINGLESTEP, p, 0, 0)

template peekUser*(p: Pid, a: clong): expr =
  ptrace(PTRACE_PEEKUSER, p, a, 0)

template getData*(p: Pid, a: clong): expr =
  ptrace(PTRACE_PEEKDATA, p, a, 0)

proc getData*[T](p: Pid, a: clong, buf: var T, length: int) =
  var i, j, k: int
  var data: CValue

  i = length div WORD_SIZE
  for x in 0..i-1:
    data.lg = getData(p, a + x * WORD_SIZE)
    if errno != 0:
      echo errno, " ", strerror(errno)
    for c in data.chars:
      if j >= length:
        break
      buf[j] = c
      inc(j)

  k = length mod WORD_SIZE
  if k != 0:
    data.lg = getData(p, a + i * WORD_SIZE)
    if errno != 0:
      echo errno, " ", strerror(errno)
    for c in data.chars:
      if j >= length:
        break
      buf[j] = c
      inc(j)

proc getString*(p: Pid, a: clong, length: int): cstring =
    result = newString(length)
    getData(p, a, result, length)

proc putData*[T: string|array](p: Pid, a: clong, buf: T, length: clong) =
  var i, j, idx: int
  var data: CValue

  i = length div WORD_SIZE
  while j < i:
    for k in 0..WORD_SIZE-1:
      idx = j * WORD_SIZE + k
      if idx >= length:
        break
      data.chars[k] = (char)buf[idx]
      ptrace(PTRACE_POKEDATA, p, a + j * WORD_SIZE, data.lg)
      if errno != 0:
        echo errno, " ", strerror(errno)
    if errno != 0:
        echo errno, " ", strerror(errno)
    inc(j)

  j = length mod WORD_SIZE
  if j != 0:
    for k in 0..j-1:
      idx = i * WORD_SIZE + k
      if idx >= length:
        break
      data.chars[k] = (char)buf[idx]
    ptrace(PTRACE_POKEDATA, p, a + i * WORD_SIZE, data.lg)
    if errno != 0:
      echo errno, " ", strerror(errno)

template putString*(p: Pid, a: clong, str: string, length: clong) =
  putData(p, a, str, length)

when isMainModule:
  var
    child: Pid
    orig_ax: clong
    a: cint

  child = fork()
  if child == 0:
    traceMe()
    discard execl("/bin/ls", "ls", nil)
  else:
    wait(addr a)

    var regs = getRegs(child)
    echo "orig_rax: ", regs.orig_rax
    if errno != 0:
      echo errno, " ", strerror(errno)

    orig_ax = peekUser(child, SYSCALL_NUM)
    if errno != 0:
      echo errno, " ", strerror(errno)
    echo "The child made a system call: ", orig_ax
    cont(child)

import posix, strutils, math

const
  WORD_SIZE* = sizeof(clong)

type
  CValue* {.union.} = object
    lg*: clong
    d*: cdouble
    f*: cfloat
    i*: cint
    ui*: cuint
    chars*: array[WORD_SIZE, cchar]

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
  PTRACE_ATTACH* = 16
  PTRACE_DETACH* = 17
  PTRACE_SYSCALL* = 24
  PTRACE_SETOPTIONS* = 0x4200
  PTRACE_GETEVENTMSG* = 0x4201
  PTRACE_GETSIGINFO* =0x4202
  PTRACE_SETSIGINFO* = 0x4203
  PTRACE_SEIZE* = 0x4206
  PTRACE_INTERRUPT* = 0x4207
  PTRACE_LISTEN* = 0x4208

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
    ECX* = 4
    EDX* = 8
    ESI* = 14
    EDI* = 16
    EBP* = 20
    EAX* = 24
    DS* = 28
    ES* = 32
    FS* = 36
    GS* = 40
    ORIG_EAX* = 44
    EIP* = 48
    CS* = 52
    EFL* = 56
    UESP* = 60
    SS* =64
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

proc ptrace*[T](request: cint, pid: Pid, a: clong, data: T): clong {.cdecl, importc, header: "sys/ptrace.h", discardable.}

template setOptions*(p: Pid, data: ptr cint) =
  ## Set ptrace options from `data`
  ptrace(PTRACE_SETOPTIONS, p, 0, data)

template getRegs*(p: Pid, regs: ptr Registers) =
  ## Copy the tracee's general-purpose or floating-point registers to the address of `regs` in the tracer
  ptrace(PTRACE_GETREGS, p, 0, regs)

template setRegs*(p: Pid, regs: ptr Registers) =
  ## Modify the tracee's general-purpose or floating-point registers from the address of `regs` in the tracer
  ptrace(PTRACE_SETREGS, p, 0, regs)

template attach*(pid: Pid) =
  ## Attach to the process specified in `pid`
  ptrace(PTRACE_ATTACH, pid, 0, 0)

template detach*(p: Pid, signal: clong = 0) =
  ## Restart the stopped tracee as for `cont` but first deattach from it
  ptrace(PTRACE_DETACH, p, 0, signal)

template cont*(p: Pid, signal: clong = 0) =
  ## Restart the stopped tracee process
  ptrace(PTRACE_CONT, p, 0, signal)

template traceMe*() =
  ## Indicate that this process is to be traced by its parent
  ptrace(PTRACE_TRACEME, 0, 0, 0)

template syscall*(p: Pid) =
  ptrace(PTRACE_SYSCALL, p, 0, 0)

template singleStep*(p: Pid) =
  ptrace(PTRACE_SINGLESTEP, p, 0, 0)

template peekUser*(p: Pid, a: clong): untyped =
  ## Read a word at offset addr in the tracee's USER area, which
  ## holds the registers and other information about the process
  ptrace(PTRACE_PEEKUSER, p, a, 0)

template getData*(p: Pid, a: clong): untyped  =
  ## Read a word at the address addr in the tracee's memory
  ptrace(PTRACE_PEEKDATA, p, a, 0)

proc getData*[T: string|cstring|array|seq](p: Pid, a: clong, buf: var T, length: int) =
  var i, j: int
  var data: CValue

  i = ceil(length / WORD_SIZE).int
  for x in 0..i-1:
    data.lg = getData(p, a + x * WORD_SIZE)
    if errno != 0:
      raise newException(IOError, "$#: $#" % [$errno, $strerror(errno)])
    for c in data.chars:
      if j >= length:
        break
      buf[j] = c
      inc(j)

proc getData*(p: Pid, a: clong, pt: pointer, length: int) {.inline.} =
  var buf = cast[cstring](pt)
  getData(p, a, buf, length)

proc getString*(p: Pid, a: clong, length: int): string =
  result = newString(length)
  getData(p, a, result, length)

proc getString*(p: Pid, a: clong): string =
  var
    i = 0
    data: CValue
  result = newString(32)

  while true:
    data.lg = getData(p, a + i)

    for j in 0..WORD_SIZE-1:
      if data.chars[j] == '\0':
        setLen(result, i + j)
        return result

      if i + j > result.len:
        setLen(result, result.len + WORD_SIZE)
      result[i + j] = data.chars[j]

    i.inc(WORD_SIZE)

proc putData*[T: string|array](p: Pid, a: clong, buf: T, length: clong) =
  ## Copy the word data to the address addr in the tracee's memory.
  var i, j, idx: int
  var data: CValue

  i = ceil(length / WORD_SIZE).int
  while j < i:
    for k in 0..WORD_SIZE-1:
      idx = j * WORD_SIZE + k
      if idx >= length:
        break
      data.chars[k] = (char)buf[idx]
      ptrace(PTRACE_POKEDATA, p, a + j * WORD_SIZE, data.lg)
      if errno != 0:
        raise newException(IOError, "$#: $#" % [$errno, $strerror(errno)])
    if errno != 0:
      raise newException(IOError, "$#: $#" % [$errno, $strerror(errno)])
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

template putString*(p: Pid, a: clong, str: string) = putData(p, a, str, str.len.clong)

when isMainModule:
  var
    child: Pid
    orig_ax: clong

  child = fork()
  if child == 0:
    traceMe()
    discard execl("/bin/ls", "ls", nil)

  else:
    wait(nil)
    var regs: Registers
    getRegs(child, addr regs)
    if errno != 0:
      echo "getRegs: ", strerror(errno)
    when hostCPU == "i386":
      echo "orig_eax: ", regs.orig_eax
    else:
      echo "orig_rax: ", regs.orig_rax
    orig_ax = peekUser(child, SYSCALL_NUM)
    if errno != 0:
      echo "peekUser: ", errno, " ", strerror(errno)
    echo "The child made a system call: ", orig_ax
    cont(child)

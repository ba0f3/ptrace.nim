import pegs, strutils, ptrace


let
  freeSpaceEntry = peg(r"{\w+}'-'(\w+)\s[rwxp-]+\s\d+\s'00:00'")

proc freeSpaceAddr*(p: int): int =
  var
    fp: File
    filename = "/proc/" & $p & "/maps"
    line: string

  fp = open(filename, fmRead)
  if fp.isNil:
    raise newException(IOError, "Unable to open " & filename & " for reading")

  while not endOfFile(fp):
    line = readLine(fp)
    echo line
    if line =~ freeSpaceEntry:
      result = parseHexInt(matches[0])
      break
  close(fp)

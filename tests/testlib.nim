{.emit: "static void init(void) __attribute__((constructor));".}

proc init*() {.exportc.} =
  echo("I am loaded and running.\x0A")

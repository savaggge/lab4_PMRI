using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Management;
using System.Runtime.InteropServices;
using System.Text.Json;
using System.Windows.Forms;

namespace lab4_PMRI
{
    public partial class Form1 : Form
    {
        public Form1()
        {
            InitializeComponent();
        }

        private void Form1_Load(object sender, EventArgs e)
        {
            var processesInfo = GetProcessesInfo();
            var json = JsonSerializer.Serialize(processesInfo, new JsonSerializerOptions { WriteIndented = true });
            File.WriteAllText("processes.json", json);
        }

        private static object GetProcessesInfo()
        {
            var processes = Process.GetProcesses().Select(p =>
            {
                string filePath = GetMainModuleFilePath(p.Id);
                bool isTrusted = filePath != null && DigitalSignatureChecker.IsTrusted(filePath);

                return new
                {
                    Id = p.Id,
                    FilePath = filePath,
                    IsTrusted = isTrusted
                };
            });

            return processes.Where(p => p.FilePath != null).ToList();
        }

        private static string GetMainModuleFilePath(int processId)
        {
            try
            {
                using (var searcher = new ManagementObjectSearcher($"SELECT ExecutablePath FROM Win32_Process WHERE ProcessId = {processId}"))
                {
                    foreach (ManagementObject obj in searcher.Get())
                    {
                        return obj["ExecutablePath"]?.ToString();
                    }
                }
            }
            catch
            {
                // Ignore processes that cannot be accessed
            }
            return null;
        }
    }
}

public static class DigitalSignatureChecker
    {
        [DllImport("wintrust.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern uint WinVerifyTrust(IntPtr hwnd, [MarshalAs(UnmanagedType.LPStruct)] Guid pgActionID, [MarshalAs(UnmanagedType.LPStruct)] WINTRUST_DATA pWVTData);

        public static bool IsTrusted(string fileName)
        {
            WINTRUST_FILE_INFO fileInfo = new WINTRUST_FILE_INFO(fileName);
            WINTRUST_DATA trustData = new WINTRUST_DATA(fileInfo);

            Guid action = new Guid("00aac56b-cd44-11d0-8cc2-00c04fc295ee");
            uint result = WinVerifyTrust(IntPtr.Zero, action, trustData);

            return result == 0;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public class WINTRUST_FILE_INFO
        {
            public uint cbStruct;
            public IntPtr pcwszFilePath;
            public IntPtr hFile;
            public IntPtr pgKnownSubject;

            public WINTRUST_FILE_INFO(string fileName)
            {
                cbStruct = (uint)Marshal.SizeOf(typeof(WINTRUST_FILE_INFO));
                pcwszFilePath = Marshal.StringToCoTaskMemUni(fileName);
                hFile = IntPtr.Zero;
                pgKnownSubject = IntPtr.Zero;
            }

            ~WINTRUST_FILE_INFO()
            {
                if (pcwszFilePath != IntPtr.Zero)
                {
                    Marshal.FreeCoTaskMem(pcwszFilePath);
                }
            }
        }

        [StructLayout(LayoutKind.Sequential)]
        public class WINTRUST_DATA
        {
            public uint cbStruct;
            public IntPtr pPolicyCallbackData;
            public IntPtr pSIPClientData;
            public uint dwUIChoice;
            public uint fdwRevocationChecks;
            public uint dwUnionChoice;
            public IntPtr pInfoStruct;
            public uint dwStateAction;
            public IntPtr hWVTStateData;
            public string pwszURLReference;
            public uint dwProvFlags;
            public uint dwUIContext;

            public WINTRUST_DATA(WINTRUST_FILE_INFO fileInfo)
            {
                cbStruct = (uint)Marshal.SizeOf(typeof(WINTRUST_DATA));
                dwUIChoice = 2;
                fdwRevocationChecks = 0;
                dwUnionChoice = 1;
                pInfoStruct = Marshal.AllocCoTaskMem(Marshal.SizeOf(typeof(WINTRUST_FILE_INFO)));
                Marshal.StructureToPtr(fileInfo, pInfoStruct, false);
                dwStateAction = 0;
                dwProvFlags = 0x00000010; // WTD_SAFER_FLAG
            }

            ~WINTRUST_DATA()
            {
                if (pInfoStruct != IntPtr.Zero)
                {
                    Marshal.FreeCoTaskMem(pInfoStruct);
                }
            }
        }
    }

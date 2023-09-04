//start
using System.Text;
using System.Linq;
using System;
﻿
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Principal;


namespace StuffNeededForWork.Lib
{
    public enum CertAltNameType
    {
        OtherName = 1,
        RFC822 = 2,
        DNS = 3,
        X400Address = 4,
        DirectoryName = 5,
        EdiPartyName = 6,
        URL = 7,
        IPAddress = 8,
        RegisteredId = 9
    }

    [Flags]
    public enum CryptEncodeFlags
    {
        CRYPT_ENCODE_ALLOC_FLAG = 0x8000,
        CRYPT_ENCODE_ENABLE_PUNYCODE_FLAG = 0x20000,
        CRYPT_UNICODE_NAME_ENCODE_DISABLE_CHECK_TYPE_FLAG = 0x40000000,
        CRYPT_UNICODE_NAME_ENCODE_ENABLE_T61_UNICODE_FLAG = unchecked((int)0x80000000),
        CRYPT_UNICODE_NAME_ENCODE_ENABLE_UTF8_UNICODE_FLAG = 0x20000000,
        CRYPT_UNICODE_NAME_ENCODE_FORCE_UTF8_UNICODE_FLAG = 0x10000000
    }
    [Flags]
    public enum CertEncodingType : int
    {
        X509 = 0x1,
        PKCS7 = 0x10000
    }
    [StructLayout(LayoutKind.Sequential)]
    public struct CRYPT_BLOB
    {
        public int cbData;
        public IntPtr pbData;
    }
    [StructLayout(LayoutKind.Sequential)]
    public struct CERT_ALT_NAME_INFO
    {
        public int cAltEntry;
        public IntPtr rgAltEntry;
    }
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct CERT_ALT_NAME_ENTRY
    {
        public CertAltNameType dwAltNameChoice;
        public CERT_ALT_NAME_ENTRY_UNION Value;
    }
    [StructLayout(LayoutKind.Explicit, CharSet = CharSet.Unicode)]
    public struct CERT_ALT_NAME_ENTRY_UNION
    {
        [FieldOffset(0)]
        public IntPtr pOtherName;
        [FieldOffset(0)]
        public IntPtr pwszRfc822Name;
        [FieldOffset(0)]
        public IntPtr pwszDNSName;
        [FieldOffset(0)]
        public CRYPT_BLOB DirectoryName;
        [FieldOffset(0)]
        public IntPtr pwszURL;
        [FieldOffset(0)]
        public CRYPT_BLOB IPAddress;
        [FieldOffset(0)]
        public IntPtr pszRegisteredID;
    }
    [StructLayout(LayoutKind.Sequential)]
    public struct CERT_OTHER_NAME
    {
        [MarshalAs(UnmanagedType.LPStr)]
        public String pszObjId;
        [MarshalAs(UnmanagedType.Struct)]
        public CRYPT_BLOB Value;
    }
    public static class CertSidExtension
    {
        [DllImport("Crypt32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CryptEncodeObjectEx(
            CertEncodingType dwCertEncodingType,
            [MarshalAs(UnmanagedType.LPStr)]
            String lpszStructType,
            IntPtr pvStructInfo,
            CryptEncodeFlags dwFlags,
            IntPtr pEncodePara,
            IntPtr pvEncoded,
            [MarshalAs(UnmanagedType.I4)]
            ref int pcbEncoded
        );
        public const string szOID_SUBJECT_ALT_NAME2 = "2.5.29.17";

        public static byte[] EncodeSidExtension(SecurityIdentifier sid)
        {
            if (sid == null)
                throw new ArgumentNullException(new string("fvq".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()));

            var stringSid = sid.Value;
            var sidOid = new string("1.3.6.1.4.1.311.25.2.1".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray());
            var unmanagedSidString = IntPtr.Zero;
            var unmanagedpOtherName = IntPtr.Zero;
            var unmanagedAltNameEntry = IntPtr.Zero;
            var unmanagedAltNameInfo = IntPtr.Zero;
            var outputPtr = IntPtr.Zero;

            try
            {
                var sidLength = stringSid.Length;


                if (sidLength > 127)
                    throw new ArgumentOutOfRangeException(new string("fvq".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()), new string("Fgevat ercerfragngvba bs gur cebivqrq frphevgl vqragvsvre zhfg abg rkprrq 127 punenpgref.".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()));

                var octetString = new byte[sidLength + 2];
                octetString[0] = 0x04; // Tag identifier for an OCTET_STRING
                octetString[1] = (byte)sidLength; // Length of the OCTET_STRING value, in bytes
                Array.Copy(Encoding.ASCII.GetBytes(stringSid), 0, octetString, 2, sidLength);

                unmanagedSidString = Marshal.AllocHGlobal(octetString.Length);
                Marshal.Copy(octetString, 0, unmanagedSidString, octetString.Length);

                var otherName = new CERT_OTHER_NAME();
                otherName.pszObjId = sidOid;
                otherName.Value = new CRYPT_BLOB();

                otherName.Value.cbData = sidLength + 2;
                otherName.Value.pbData = unmanagedSidString;

                unmanagedpOtherName = Marshal.AllocHGlobal(Marshal.SizeOf(otherName));
                Marshal.StructureToPtr(otherName, unmanagedpOtherName, false);

                var altName = new CERT_ALT_NAME_ENTRY_UNION();
                altName.pOtherName = unmanagedpOtherName;

                var altNameEntry = new CERT_ALT_NAME_ENTRY();
                altNameEntry.dwAltNameChoice = CertAltNameType.OtherName;
                altNameEntry.Value = altName;

                unmanagedAltNameEntry = Marshal.AllocHGlobal(Marshal.SizeOf(altNameEntry));
                Marshal.StructureToPtr(altNameEntry, unmanagedAltNameEntry, false);

                var altNames = new CERT_ALT_NAME_INFO();
                altNames.cAltEntry = 1;
                altNames.rgAltEntry = unmanagedAltNameEntry;

                unmanagedAltNameInfo = Marshal.AllocHGlobal(Marshal.SizeOf(altNames));
                Marshal.StructureToPtr(altNames, unmanagedAltNameInfo, false);

                int resultSize = 0;
                var result = CryptEncodeObjectEx(CertEncodingType.X509, szOID_SUBJECT_ALT_NAME2, unmanagedAltNameInfo, 0, IntPtr.Zero, outputPtr, ref resultSize);
                if (resultSize > 1)
                {
                    outputPtr = Marshal.AllocHGlobal(resultSize);
                    result = CryptEncodeObjectEx(CertEncodingType.X509, szOID_SUBJECT_ALT_NAME2, unmanagedAltNameInfo, 0, IntPtr.Zero, outputPtr, ref resultSize);
                    var output = new byte[resultSize];
                    Marshal.Copy(outputPtr, output, 0, resultSize);
                    return output;
                }
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }
            finally
            {
                if (unmanagedSidString != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(unmanagedSidString);
                }
                if (unmanagedpOtherName != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(unmanagedpOtherName);
                }
                if (unmanagedAltNameEntry != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(unmanagedAltNameEntry);
                }
                if (unmanagedAltNameInfo != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(unmanagedAltNameInfo);
                }
                if (outputPtr != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(outputPtr);
                }
            }
        }
    }
}
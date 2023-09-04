//start
using System.Text;
using System.Linq;
using System;
﻿
using System.Collections.Generic;
using System.DirectoryServices;
using System.Security;
using System.Security.AccessControl;
using System.Security.Cryptography.X509Certificates;
using System.Security.Principal;
using StuffNeededForWork.Lib;
using Microsoft.Win32;

namespace StuffNeededForWork.Domain
{
    class CertificateDTO
    {
        public string? SubjectName { get; }
        public string? Thumbprint { get; }
        public string? Serial { get; }
        public string? StartDate { get; }
        public string? EndDate { get; }
        public List<string>? CertChain { get; }

        public CertificateDTO(X509Certificate2 ca)
        {
            SubjectName = ca.SubjectName.Name;
            Thumbprint = ca.Thumbprint;
            Serial = ca.SerialNumber;
            StartDate = ca.NotBefore.ToString(); ;
            EndDate = ca.NotAfter.ToString();

            var chain = new X509Chain();
            chain.Build(ca);
            var names = new List<string>();
            foreach (var elem in chain.ChainElements)
            {
                names.Add(elem.Certificate.SubjectName.Name.Replace(" ", ""));
            }

            CertChain = names;
        }
    }

    class EnterpriseCertificateAuthorityACE
    {
        public string? Type { get; }
        public string? Rights { get; }
        public string? Principal { get; }

        public EnterpriseCertificateAuthorityACE(AccessControlType? type, CertificationAuthorityRights? rights, string? principal)
        {
            Type = type.ToString();
            Rights = rights.ToString();
            Principal = principal;
        }
    }

    class EnterpriseCertificateAuthorityACL
    {
        public string? Owner { get; }
        public List<EnterpriseCertificateAuthorityACE> ACEs { get; }

        public EnterpriseCertificateAuthorityACL(ActiveDirectorySecurity securityDescriptor)
        {
            Owner = ((SecurityIdentifier)securityDescriptor.GetOwner(typeof(SecurityIdentifier))).Value.ToString();
            var rules = securityDescriptor.GetAccessRules(true, true, typeof(SecurityIdentifier));
            ACEs = new List<EnterpriseCertificateAuthorityACE>();

            foreach (ActiveDirectoryAccessRule rule in rules)
            {
                var ace = new EnterpriseCertificateAuthorityACE(
                    rule.AccessControlType,
                    (CertificationAuthorityRights)rule.ActiveDirectoryRights,
                    ((SecurityIdentifier)rule.IdentityReference).Value.ToString()
                ); ;

                ACEs.Add(ace);
            }
        }
    }

    class EnterpriseCertificateAuthorityDTO
    {
        public string? Name { get; }
        public string? DnsHostname { get; }
        public string? DomainName { get; }

        public Guid? Guid { get; }
        public string? Flags { get; }
        public List<CertificateDTO>? Certificates { get; }

        public List<string>? Templates { get; }

        public bool? EDITF_ATTRIBUTESUBJECTALTNAME2 { get; }

        public EnterpriseCertificateAuthorityACL? ACL { get; }

        public List<EnrollmentAgentRestriction>? EnrollmentAgentRestrictions { get; }

        public EnterpriseCertificateAuthorityDTO(EnterpriseCertificateAuthority ca)
        {
            ActiveDirectorySecurity? securityDescriptor = null;
            RawSecurityDescriptor? eaSecurityDescriptor = null;
            bool? userSpecifiesSanEnabled = null;
            try
            {
                securityDescriptor = ca.GetServerSecurityFromRegistry();
            }
            catch
            {
            }

            try
            {
                eaSecurityDescriptor = ca.GetEnrollmentAgentSecurity();
            }
            catch
            {
            }

            try
            {
                userSpecifiesSanEnabled = ca.IsUserSpecifiesSanEnabled();
            }
            catch
            {
            }

            Name = ca?.Name;
            DomainName = ca?.DomainName;
            Guid = ca?.Guid;
            DnsHostname = ca?.DnsHostname;
            Flags = ca?.Flags.ToString();
            Templates = ca?.Templates;
            EDITF_ATTRIBUTESUBJECTALTNAME2 = userSpecifiesSanEnabled;

            Certificates = new List<CertificateDTO>();
            if (ca?.Certificates != null)
            {
                foreach (var cert in ca.Certificates)
                {
                    Certificates.Add(new CertificateDTO(cert));
                }
            }

            ACL = securityDescriptor == null ? null : new EnterpriseCertificateAuthorityACL(securityDescriptor);

            if (eaSecurityDescriptor == null)
            {
                EnrollmentAgentRestrictions = null;
            }
            else
            {
                EnrollmentAgentRestrictions = new List<EnrollmentAgentRestriction>();

                foreach (CommonAce ace in eaSecurityDescriptor.DiscretionaryAcl)
                {
                    EnrollmentAgentRestrictions.Add(new EnrollmentAgentRestriction(ace));
                }
            }
        }
    }

    class EnterpriseCertificateAuthority : CertificateAuthority
    {
        public List<string>? Templates { get; }
        public string? DnsHostname { get; }
        public string? FullName => $"{DnsHostname}\\{Name}";

        public EnterpriseCertificateAuthority(string distinguishedName, string? name, string? domainName, Guid? guid, string? dnsHostname, PkiCertificateAuthorityFlags? flags, List<X509Certificate2>? certificates, ActiveDirectorySecurity? securityDescriptor, List<string>? templates)
            : base(distinguishedName, name, domainName, guid, flags, certificates, securityDescriptor)
        {
            DnsHostname = dnsHostname;
            Templates = templates;
        }

        public ActiveDirectorySecurity? GetServerSecurityFromRegistry()
        {
            if (DnsHostname == null) throw new NullReferenceException(new string("QafUbfganzr vf ahyy".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()));
            if (Name == null) throw new NullReferenceException(new string("Anzr vf ahyy".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()));

            RegistryKey baseKey;
            try
            {
                baseKey = RegistryKey.OpenRemoteBaseKey(RegistryHive.LocalMachine, DnsHostname);
            }
            catch (Exception e)
            {
                Console.WriteLine($"[X] Could not connect to the HKLM hive - {e.Message}");
                return null;
            }

            byte[] security;
            try
            {
                var key = baseKey.OpenSubKey($"SYSTEM\\CurrentControlSet\\Services\\CertSvc\\Configuration\\{Name}");
                security = (byte[])key.GetValue(new string("Frphevgl".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()));
            }
            catch (SecurityException e)
            {
                Console.WriteLine($"[X] Could not access the 'Security' registry value: {e.Message}");
                return null;
            }

            var securityDescriptor = new ActiveDirectorySecurity();
            securityDescriptor.SetSecurityDescriptorBinaryForm(security, AccessControlSections.All);

            return securityDescriptor;
        }

        public RawSecurityDescriptor? GetEnrollmentAgentSecurity()
        {
            RegistryKey baseKey;
            try
            {
                baseKey = RegistryKey.OpenRemoteBaseKey(RegistryHive.LocalMachine, DnsHostname);
            }
            catch (Exception e)
            {
                throw new Exception($"Could not connect to the HKLM hive - {e.Message}");
            }

            byte[] security;
            try
            {
                var key = baseKey.OpenSubKey($"SYSTEM\\CurrentControlSet\\Services\\CertSvc\\Configuration\\{Name}");
                security = (byte[])key.GetValue(new string("RaebyyzragNtragEvtugf".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()));
            }
            catch (SecurityException e)
            {
                throw new Exception($"Could not access the 'EnrollmentAgentRights' registry value: {e.Message}");
            }

            return security == null ? null : new RawSecurityDescriptor(security, 0);
        }


        public bool IsUserSpecifiesSanEnabled()
        {
            if (DnsHostname == null) throw new NullReferenceException(new string("QafUbfganzr vf ahyy".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()));
            if (Name == null) throw new NullReferenceException(new string("Anzr vf ahyy".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()));

            RegistryKey baseKey;
            try
            {
                baseKey = RegistryKey.OpenRemoteBaseKey(RegistryHive.LocalMachine, DnsHostname);
            }
            catch (Exception e)
            {
                throw new Exception($"Could not connect to the HKLM hive - {e.Message}");
            }

            int editFlags;
            try
            {
                var key = baseKey.OpenSubKey($"SYSTEM\\CurrentControlSet\\Services\\CertSvc\\Configuration\\{Name}\\PolicyModules\\CertificateAuthority_MicrosoftDefault.Policy");
                editFlags = (int)key.GetValue(new string("RqvgSyntf".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()));
            }
            catch (SecurityException e)
            {
                throw new Exception($"Could not access the EditFlags registry value: {e.Message}");
            }

            return (editFlags & 0x00040000) == 0x00040000;
        }

        public CertificateAuthorityWebServices GetWebServices()
        {
            if (DnsHostname == null) throw new NullReferenceException(new string("QafUbfganzr vf ahyy".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()));

            var webservices = new CertificateAuthorityWebServices();

            var protocols = new List<string>() { new string("uggc://".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()), new string("uggcf://".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()) };

            protocols.ForEach(p =>
            {
                var LegacyAspEnrollmentUrl = $"{p}{DnsHostname}/certsrv/";
                var enrollmentWebServiceUrl = $"{p}{DnsHostname}/{Name}_CES_Kerberos/service.svc";
                var enrollmentPolicyWebServiceUrl = $"{p}{DnsHostname}/ADPolicyProvider_CEP_Kerberos/service.svc";
                var ndesEnrollmentUrl = $"{p}{DnsHostname}/certsrv/mscep/";

                if (HttpUtil.UrlExists(LegacyAspEnrollmentUrl, new string("AGYZ".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray())))
                    webservices.LegacyAspEnrollmentUrls.Add(LegacyAspEnrollmentUrl);

                if (HttpUtil.UrlExists(enrollmentWebServiceUrl))
                    webservices.EnrollmentWebServiceUrls.Add(enrollmentWebServiceUrl);

                if (HttpUtil.UrlExists(enrollmentPolicyWebServiceUrl))
                    webservices.EnrollmentPolicyWebServiceUrls.Add(enrollmentPolicyWebServiceUrl);

                if (HttpUtil.UrlExists(ndesEnrollmentUrl))
                    webservices.NetworkDeviceEnrollmentServiceUrls.Add(ndesEnrollmentUrl);
            });

            return webservices;
        }
    }
}

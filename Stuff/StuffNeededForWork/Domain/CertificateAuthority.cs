//start
using System.Text;
using System.Linq;
using System;
﻿
using System.Collections.Generic;
using System.DirectoryServices;
using System.Security.Cryptography.X509Certificates;

namespace StuffNeededForWork.Domain
{
    [Flags]
    public enum CertificationAuthorityRights : uint
    {
        ManageCA = 1,               // Administrator
        ManageCertificates = 2,     // Officer
        Auditor = 4,
        Operator = 8,
        Read = 256,
        Enroll = 512,
    }

    [Flags]
    public enum PkiCertificateAuthorityFlags : uint
    {
        NO_TEMPLATE_SUPPORT = 0x00000001,
        SUPPORTS_NT_AUTHENTICATION = 0x00000002,
        CA_SUPPORTS_MANUAL_AUTHENTICATION = 0x00000004,
        CA_SERVERTYPE_ADVANCED = 0x00000008,
    }

    public class CertificateAuthority : ADObject, IDisposable
    {
        public string? Name { get; }
        public string? DomainName { get; }

        public Guid? Guid { get; }
        public PkiCertificateAuthorityFlags? Flags { get; }
        public List<X509Certificate2>? Certificates { get; private set; }


        private bool _disposed;
        public CertificateAuthority(string distinguishedName, string? name, string? domainName, Guid? guid, PkiCertificateAuthorityFlags? flags, List<X509Certificate2>? certificates, ActiveDirectorySecurity? securityDescriptor)
            : base(distinguishedName, securityDescriptor)
        {
            Name = name;
            DomainName = domainName;
            Guid = guid;
            Flags = flags;
            Certificates = certificates;
        }

        ~CertificateAuthority()
        {
            Dispose(false);
        }

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        protected virtual void Dispose(bool disposing)
        {
            if (_disposed) return;

            if (disposing)
            {

                if (Certificates != null && Certificates.Any())
                {
                    Certificates.ForEach(c => c.Reset());
                    Certificates = new List<X509Certificate2>();
                }
            }

            _disposed = true;
        }
    }
}

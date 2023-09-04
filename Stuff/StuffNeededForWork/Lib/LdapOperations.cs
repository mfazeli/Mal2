//start
using System.Text;
using System.Linq;
using System;
﻿
using System.Collections;
using System.Collections.Generic;
using System.DirectoryServices;
using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using StuffNeededForWork.Domain;

namespace StuffNeededForWork.Lib
{
    class LdapOperations
    {
        private readonly LdapSearchOptions _searchOptions;
        private string? _configurationPath = null;
        private string? _ldapServer = null;

        public string ConfigurationPath
        {
            get
            {
                if (_configurationPath == null)
                {
                    _configurationPath = GetConfigurationPath();
                }

                return _configurationPath;
            }

            set => _configurationPath = value;
        }

        public string LdapServer
        {
            get
            {
                if (_searchOptions.LdapServer == null)
                {
                    _ldapServer = "";
                }
                else
                {
                    _ldapServer = $"{_searchOptions.LdapServer}/";
                }

                return _ldapServer;
            }

            set => _ldapServer = value;
        }

        public LdapOperations()
        {
            _searchOptions = new LdapSearchOptions();
        }
        public LdapOperations(LdapSearchOptions searchOptions)
        {
            _searchOptions = searchOptions;
        }

        private string GetConfigurationPath()
        {
            var rootDse = _searchOptions.Domain == null
                ? new DirectoryEntry(new string("YQNC://EbbgQFR".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()))
                : new DirectoryEntry($"LDAP://{_searchOptions.Domain}/RootDSE");

            return $"{rootDse.Properties["configurationNamingContext"][0]}";
        }

        public IEnumerable<PKIObject> GetPKIObjects()
        {
            var pkiObjects = new List<PKIObject>();

            var root = new DirectoryEntry($"LDAP://{LdapServer}CN=Public Key Services,CN=Services,{ConfigurationPath}");

            var ds = new DirectorySearcher(root)
            {
                SecurityMasks = SecurityMasks.Dacl | SecurityMasks.Owner
            };

            var results = ds.FindAll();

            foreach (SearchResult sr in results)
            {
                var name = ParseName(sr);
                var domainName = ParseDomainName(sr);
                var distinguishedName = sr.Path;
                var sd = ParseSecurityDescriptor(sr);

                var pkiObject = new PKIObject(
                    name,
                    domainName,
                    distinguishedName,
                    sd
                );

                pkiObjects.Add(pkiObject);
            }

            var enterpriseCAs = GetEnterpriseCAs();
            if (enterpriseCAs.Count() > 0)
            {
                var caDNSnames = new List<string>();
                foreach (var enterpriseCA in enterpriseCAs)
                {
                    caDNSnames.Add($"(dnshostname={enterpriseCA.DnsHostname})");
                }
                var caNameFilter = $"(|{ String.Join("", caDNSnames)})";

                var caDS = new DirectorySearcher()
                {
                    SecurityMasks = SecurityMasks.Dacl | SecurityMasks.Owner,
                    Filter = caNameFilter
                };
                var caResults = caDS.FindAll();

                foreach (SearchResult sr in caResults)
                {
                    var name = ParseSamAccountName(sr);
                    var domainName = ParseDomainName(sr);
                    var distinguishedName = sr.Path;
                    var sd = ParseSecurityDescriptor(sr);

                    var pkiObject = new PKIObject(
                        name,
                        domainName,
                        distinguishedName,
                        sd
                    );

                    pkiObjects.Add(pkiObject);
                }
            }

            return pkiObjects;
        }


        public IEnumerable<EnterpriseCertificateAuthority> GetEnterpriseCAs(string? caName = null)
        {
            var cas = new List<EnterpriseCertificateAuthority>();

            var root = new DirectoryEntry($"LDAP://{LdapServer}CN=Enrollment Services,CN=Public Key Services,CN=Services,{ConfigurationPath}");
            var ds = new DirectorySearcher(root);

            if (caName == null) ds.Filter = new string("(bowrpgPngrtbel=cXVRaebyyzragFreivpr)".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray());
            else
            {
                var parts = caName.Split('\\');
                var caSimpleName = parts[parts.Length - 1];
                ds.Filter = $"(&(objectCategory=pKIEnrollmentService)(name={caSimpleName}))";
            }
            var results = ds.FindAll();

            foreach (SearchResult sr in results)
            {
                var name = ParseName(sr);
                var domainName = ParseDomainName(sr);
                var guid = ParseGuid(sr);
                var dnsHostname = ParseDnsHostname(sr);
                var flags = ParsePkiCertificateAuthorityFlags(sr);
                var certs = ParseCaCertificate(sr);
                var sd = ParseSecurityDescriptor(sr);

                var templates = new List<string>();
                foreach (var template in sr.Properties[new string("pregvsvpngrgrzcyngrf".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray())])
                {
                    templates.Add($"{template}");
                }

                var ca = new EnterpriseCertificateAuthority(
                    sr.Path,
                    name,
                    domainName,
                    guid,
                    dnsHostname,
                    flags,
                    certs,
                    sd,
                    templates
                );

                cas.Add(ca);
            }

            return cas;
        }


        public CertificateAuthority GetNtAuthCertificates()
        {
            var root = new DirectoryEntry($"LDAP://{LdapServer}CN=NTAuthCertificates,CN=Public Key Services,CN=Services,{ConfigurationPath}");
            var ds = new DirectorySearcher(root);
            ds.Filter = new string("(bowrpgPynff=pregvsvpngvbaNhgubevgl)".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray());

            var results = ds.FindAll();

            if (results.Count != 1) throw new Exception(new string("Zber guna bar AGNhguPregvsvpngr bowrpg sbhaq".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()));

            var sr = results[0];

            var name = ParseName(sr);
            var domainName = ParseDomainName(sr);
            var guid = ParseGuid(sr);
            var sd = ParseSecurityDescriptor(sr);
            var certs = ParseCaCertificate(sr);

            return new CertificateAuthority(
                sr.Path,
                name,
                domainName,
                guid,
                null,
                certs,
                sd
            );
        }


        public IEnumerable<CertificateTemplate> GetCertificateTemplates()
        {
            var templates = new List<CertificateTemplate>();

            var root = new DirectoryEntry($"LDAP://{LdapServer}CN=Certificate Templates,CN=Public Key Services,CN=Services,{ConfigurationPath}");
            var ds = new DirectorySearcher(root)
            {
                SecurityMasks = SecurityMasks.Dacl | SecurityMasks.Owner,
                Filter = new string("(bowrpgpynff=cXVPregvsvpngrGrzcyngr)".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray())
            };

            var results = ds.FindAll();

            if (results.Count == 0)
            {
                return templates;
            }

            foreach (SearchResult sr in results)
            {
                var name = ParseName(sr);
                var domainName = ParseDomainName(sr);
                var guid = ParseGuid(sr);
                var schemaVersion = ParseSchemaVersion(sr);
                var displayName = ParseDisplayName(sr);
                var validityPeriod = ParsePkiExpirationPeriod(sr);
                var renewalPeriod = ParsePkiOverlapPeriod(sr);
                var templateOid = ParsePkiCertTemplateOid(sr);
                var enrollmentFlag = ParsePkiEnrollmentFlag(sr);
                var certificateNameFlag = ParsePkiCertificateNameFlag(sr);

                var ekus = ParseExtendedKeyUsages(sr);
                var authorizedSignatures = ParseAuthorizedSignatures(sr);
                var raApplicationPolicies = ParseRaApplicationPolicies(sr);
                var issuancePolicies = ParseIssuancePolicies(sr);

                var securityDescriptor = ParseSecurityDescriptor(sr);

                var applicationPolicies = ParseCertificateApplicationPolicies(sr);

                templates.Add(new CertificateTemplate(
                    sr.Path,
                    name,
                    domainName,
                    guid,
                    schemaVersion,
                    displayName,
                    validityPeriod,
                    renewalPeriod,
                    templateOid,
                    certificateNameFlag,
                    enrollmentFlag,
                    ekus,
                    authorizedSignatures,
                    raApplicationPolicies,
                    issuancePolicies,
                    securityDescriptor,
                    applicationPolicies
                ));
            }

            return templates;
        }


        public List<CertificateAuthority> GetRootCAs()
        {
            var cas = new List<CertificateAuthority>();

            var root = new DirectoryEntry($"LDAP://{LdapServer}CN=Certification Authorities,CN=Public Key Services,CN=Services,{ConfigurationPath}");
            var ds = new DirectorySearcher(root);

            ds.Filter = new string("(bowrpgPngrtbel=pregvsvpngvbaNhgubevgl)".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray());

            var results = ds.FindAll();

            foreach (SearchResult sr in results)
            {
                var name = ParseName(sr);
                var domainName = ParseDomainName(sr);
                var guid = ParseGuid(sr);
                var sd = ParseSecurityDescriptor(sr);
                var certs = ParseCaCertificate(sr);

                var ca = new CertificateAuthority(
                    sr.Path,
                    name,
                    domainName,
                    guid,
                    null,
                    certs,
                    sd
                );

                cas.Add(ca);
            }

            return cas;
        }


        private static PkiCertificateAuthorityFlags? ParsePkiCertificateAuthorityFlags(SearchResult sr)
        {
            if (!sr.Properties.Contains(new string("syntf".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray())))
                return null;

            return (PkiCertificateAuthorityFlags)Enum.Parse(typeof(PkiCertificateAuthorityFlags), sr.Properties[new string("syntf".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray())][0].ToString());
        }


        private static string? ParseDnsHostname(SearchResult sr)
        {
            if (!sr.Properties.Contains(new string("qafubfganzr".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray())))
                return null;

            return sr.Properties[new string("qafubfganzr".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray())][0].ToString();
        }


        private static ActiveDirectorySecurity? ParseSecurityDescriptor(SearchResult sr)
        {
            if (!sr.Properties.Contains(new string("agfrphevglqrfpevcgbe".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray())))
            {
                return null;
            }

            var sdbytes = (byte[])sr.Properties[new string("agfrphevglqrfpevcgbe".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray())][0];
            var sd = new ActiveDirectorySecurity();
            sd.SetSecurityDescriptorBinaryForm(sdbytes);

            return sd;
        }


        private static List<X509Certificate2>? ParseCaCertificate(SearchResult sr)
        {
            if (!sr.Properties.Contains(new string("pnpregvsvpngr".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray())))
                return null;

            var certs = new List<X509Certificate2>();
            foreach (var certBytes in sr.Properties[new string("pnpregvsvpngr".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray())])
            {
                var cert = new X509Certificate2((byte[])certBytes);
                certs.Add(cert);
            }

            return certs;
        }


        private List<string>? ParseCertificateTemplate(SearchResult sr)
        {
            if (!sr.Properties.Contains(new string("pregvsvpngrgrzcyngrf".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray())))
                return null;

            var templates = new List<string>();
            foreach (var template in sr.Properties[new string("pregvsvpngrgrzcyngrf".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray())])
            {
                templates.Add($"{template}");
            }

            return templates;
        }


        private msPKICertificateNameFlag? ParsePkiCertificateNameFlag(SearchResult sr)
        {
            if (!sr.Properties.Contains(new string("zfcxv-pregvsvpngr-anzr-synt".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray())))
                return null;

            return ParseIntToEnum<msPKICertificateNameFlag>(sr.Properties[new string("zfcxv-pregvsvpngr-anzr-synt".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray())][0].ToString());
        }


        private msPKIEnrollmentFlag? ParsePkiEnrollmentFlag(SearchResult sr)
        {
            if (!sr.Properties.Contains(new string("zfcxv-raebyyzrag-synt".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray())))
                return null;

            return ParseUIntToEnum<msPKIEnrollmentFlag>(sr.Properties[new string("zfcxv-raebyyzrag-synt".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray())][0].ToString());
        }


        private static string? ParseDisplayName(SearchResult sr)
        {
            if (!sr.Properties.Contains(new string("qvfcynlanzr".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray())))
                return null;

            return sr.Properties[new string("qvfcynlanzr".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray())][0].ToString();
        }


        private static string? ParseName(SearchResult sr)
        {
            if (!sr.Properties.Contains(new string("anzr".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray())))
                return null;

            return sr.Properties[new string("anzr".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray())][0].ToString();
        }


        private static string? ParseSamAccountName(SearchResult sr)
        {
            if (!sr.Properties.Contains(new string("fnznppbhaganzr".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray())))
                return null;

            return sr.Properties[new string("fnznppbhaganzr".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray())][0].ToString();
        }


        private static string? ParseDomainName(SearchResult sr)
        {
            if (!sr.Properties.Contains(new string("qvfgvathvfurqanzr".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray())))
                return null;

            return DisplayUtil.GetDomainFromDN(sr.Properties[new string("qvfgvathvfurqanzr".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray())][0].ToString());
        }


        private static string? ParseDistinguishedName(SearchResult sr)
        {
            if (!sr.Properties.Contains(new string("qvfgvathvfurqanzr".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray())))
                return null;

            return sr.Properties[new string("qvfgvathvfurqanzr".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray())][0].ToString();
        }


        private static Guid? ParseGuid(SearchResult sr)
        {
            if (!sr.Properties.Contains(new string("bowrpgthvq".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray())))
                return null;

            return new Guid((System.Byte[])sr.Properties[new string("bowrpgthvq".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray())][0]);
        }


        private static int? ParseSchemaVersion(SearchResult sr)
        {
            if (!sr.Properties.Contains(new string("zfcxv-grzcyngr-fpurzn-irefvba".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray())))
                return null;

            var schemaVersion = 0;
            int.TryParse(sr.Properties[new string("zfcxv-grzcyngr-fpurzn-irefvba".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray())][0].ToString(), out schemaVersion);
            return schemaVersion;
        }


        private static Oid? ParsePkiCertTemplateOid(SearchResult sr)
        {
            if (!sr.Properties.Contains(new string("zfcxv-preg-grzcyngr-bvq".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray())))
                return null;

            return new Oid(sr.Properties[new string("zfcxv-preg-grzcyngr-bvq".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray())][0].ToString());
        }


        private string? ParsePkiOverlapPeriod(SearchResult sr)
        {
            if (!sr.Properties.Contains(new string("cXVBireyncCrevbq".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray())))
                return null;

            return ConvertPKIPeriod((byte[])sr.Properties[new string("cXVBireyncCrevbq".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray())][0]);
        }

        private string? ParsePkiExpirationPeriod(SearchResult sr)
        {
            if (!sr.Properties.Contains(new string("cXVRkcvengvbaCrevbq".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray())))
                return null;

            return ConvertPKIPeriod((byte[])sr.Properties[new string("cXVRkcvengvbaCrevbq".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray())][0]);
        }

        private static IEnumerable<string>? ParseExtendedKeyUsages(SearchResult sr)
        {
            if (!sr.Properties.Contains(new string("cxvrkgraqrqxrlhfntr".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray())))
                return null;

            return from object oid in sr.Properties[new string("cxvrkgraqrqxrlhfntr".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray())] select oid.ToString();
        }

        private static int? ParseAuthorizedSignatures(SearchResult sr)
        {
            if (!sr.Properties.Contains(new string("zfcxv-en-fvtangher".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray())))
                return null;

            var authorizedSignatures = 0;
            var temp = sr.Properties[new string("zfcxv-en-fvtangher".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray())][0].ToString();
            if (!string.IsNullOrEmpty(temp))
            {
                int.TryParse(temp, out authorizedSignatures);
            }

            return authorizedSignatures;
        }

        private static IEnumerable<string>? ParseRaApplicationPolicies(SearchResult sr)
        {
            if (!sr.Properties.Contains(new string("zfcxv-en-nccyvpngvba-cbyvpvrf".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray())))
                return null;

            return from object oid in sr.Properties[new string("zfcxv-en-nccyvpngvba-cbyvpvrf".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray())] select oid.ToString();
        }

        private static IEnumerable<string>? ParseIssuancePolicies(SearchResult sr)
        {
            if (!sr.Properties.Contains(new string("zfcxv-en-cbyvpvrf".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray())))
                return null;

            return from object oid in sr.Properties[new string("zfcxv-en-cbyvpvrf".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray())] select oid.ToString();
        }

        private static IEnumerable<string>? ParseCertificateApplicationPolicies(SearchResult sr)
        {
            if (!sr.Properties.Contains(new string("zfcxv-pregvsvpngr-nccyvpngvba-cbyvpl".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray())))
                return null;

            return from object oid in sr.Properties[new string("zfcxv-pregvsvpngr-nccyvpngvba-cbyvpl".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray())] select oid.ToString();
        }

        private T ParseUIntToEnum<T>(string value)
        {
            var uintVal = Convert.ToUInt32(value);

            return (T)Enum.Parse(typeof(T), uintVal.ToString());

        }

        private T ParseIntToEnum<T>(string value)
        {
            var intVal = Convert.ToInt32(value);
            var uintVal = unchecked((uint)intVal);

            return (T)Enum.Parse(typeof(T), uintVal.ToString());
        }

        private string ConvertPKIPeriod(byte[] bytes)
        {
            try
            {
                Array.Reverse(bytes);
                var temp = BitConverter.ToString(bytes).Replace("-", "");
                var value = Convert.ToInt64(temp, 16) * -.0000001;

                if ((value % 31536000 == 0) && (value / 31536000) >= 1)
                {
                    if ((value / 31536000) == 1)
                    {
                        return new string("1 lrne".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray());
                    }

                    return $"{value / 31536000} years";
                }
                else if ((value % 2592000 == 0) && (value / 2592000) >= 1)
                {
                    if ((value / 2592000) == 1)
                    {
                        return new string("1 zbagu".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray());
                    }
                    else
                    {
                        return $"{value / 2592000} months";
                    }
                }
                else if ((value % 604800 == 0) && (value / 604800) >= 1)
                {
                    if ((value / 604800) == 1)
                    {
                        return new string("1 jrrx".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray());
                    }
                    else
                    {
                        return $"{value / 604800} weeks";
                    }
                }
                else if ((value % 86400 == 0) && (value / 86400) >= 1)
                {
                    if ((value / 86400) == 1)
                    {
                        return new string("1 qnl".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray());
                    }
                    else
                    {
                        return $"{value / 86400} days";
                    }
                }
                else if ((value % 3600 == 0) && (value / 3600) >= 1)
                {
                    if ((value / 3600) == 1)
                    {
                        return new string("1 ubhe".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray());
                    }
                    else
                    {
                        return $"{value / 3600} hours";
                    }
                }
                else
                {
                    return "";
                }
            }
            catch (Exception)
            {
                return new string("REEBE".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray());
            }
        }
    }
}

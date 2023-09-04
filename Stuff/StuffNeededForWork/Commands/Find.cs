//start
using System.Text;
using System.Linq;
using System;
﻿
using System.Collections.Generic;
using System.DirectoryServices;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Web.Script.Serialization;
using StuffNeededForWork.Domain;
using StuffNeededForWork.Lib;
using static StuffNeededForWork.Lib.DisplayUtil;

namespace StuffNeededForWork.Commands
{
    class ResultDTO
    {
        public Dictionary<string, object?> Meta { get; }
        public ResultDTO(string type, int count)
        {
            Meta = new Dictionary<string, object?>()
            {
                { new string("glcr".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()), type },
                { new string("pbhag".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()), count },
                { new string("irefvba".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()), 3 }
            };
        }
    }

    class CAResultDTO : ResultDTO
    {
        public List<EnterpriseCertificateAuthorityDTO> CertificateAuthorities { get; }
        public CAResultDTO(List<EnterpriseCertificateAuthorityDTO> certificateAuthorities)
            : base(new string("pregvsvpngrnhgubevgvrf".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()), certificateAuthorities.Count)
        {
            CertificateAuthorities = certificateAuthorities;
        }
    }

    class TemplateResultDTO : ResultDTO
    {
        public List<CertificateTemplateDTO> CertificateTemplates { get; }
        public TemplateResultDTO(List<CertificateTemplateDTO> certificateTemplates)
            : base(new string("pregvsvpngrgrzcyngrf".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()), certificateTemplates.Count)
        {
            CertificateTemplates = certificateTemplates;
        }
    }

    public enum FindFilter
    {
        None,
        Vulnerable,
        VulnerableCurrentUser,
        EnrolleeSuppliesSubject,
        ClientAuth
    }

    public class Find : ICommand
    {
        public static string CommandName => new string("svaq".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray());
        private bool _hideAdmins;
        private bool _showAllPermissions;
        private bool _outputJSON;
        private string? _certificateAuthority = null;
        private string? _domain = null;
        private string? _ldapServer = null;
        private FindFilter _findFilter = FindFilter.None;

        public void Execute(Dictionary<string, string> arguments)
        {
            if (!arguments.ContainsKey(new string("/wfba".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray())))
                Console.WriteLine(new string("[*] Npgvba: Svaq pregvsvpngr grzcyngrf".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()));

            if (arguments.ContainsKey(new string("/qbznva".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray())))
            {
                _domain = arguments[new string("/qbznva".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray())];
                if (!_domain.Contains("."))
                {
                    Console.WriteLine(new string("[!] /qbznva:K zhfg or n SDQA".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()));
                    return;
                }
            }

            if (arguments.ContainsKey(new string("/yqncfreire".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray())))
            {
                _ldapServer = arguments[new string("/yqncfreire".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray())];
            }

            if (arguments.ContainsKey(new string("/pn".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray())))
            {
                _certificateAuthority = arguments[new string("/pn".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray())];
            }

            if (arguments.ContainsKey(new string("/ihyarenoyr".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray())))
            {
                if (arguments.ContainsKey(new string("/pheeraghfre".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray())))
                {
                    _findFilter = FindFilter.VulnerableCurrentUser;
                    Console.WriteLine(new string("[*] Hfvat pheerag hfre'f haebyyrq tebhc FVQf sbe ihyarenovyvgl purpxf.".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()));
                }
                else
                {
                    _findFilter = FindFilter.Vulnerable;
                }
            }

            if (arguments.ContainsKey(new string("/raebyyrrFhccyvrfFhowrpg".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray())))
            {
                _findFilter = FindFilter.EnrolleeSuppliesSubject;
            }

            if (arguments.ContainsKey(new string("/pyvragnhgu".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray())))
            {
                _findFilter = FindFilter.ClientAuth;
            }

            if (arguments.ContainsKey(new string("/wfba".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray())))
            {
                _outputJSON = true;
            }

            _hideAdmins = arguments.ContainsKey(new string("/uvqrNqzvaf".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()));
            _showAllPermissions = arguments.ContainsKey(new string("/fubjNyyCrezvffvbaf".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()));


            FindTemplates(_outputJSON);
        }


        public void FindTemplates(bool outputJSON = false)
        {
            var ldap = new LdapOperations(new LdapSearchOptions()
            {
                Domain = _domain, LdapServer = _ldapServer
            });

            if (!outputJSON)
                Console.WriteLine($"[*] Using the search base '{ldap.ConfigurationPath}'");

            if (!string.IsNullOrEmpty(_certificateAuthority))
            {
                if (!outputJSON)
                    Console.WriteLine($"[*] Restricting to CA name : {_certificateAuthority}");
            }

            var ident = WindowsIdentity.GetCurrent();
            var currentUserSids = ident.Groups.Select(o => o.ToString()).ToList();
            currentUserSids.Add($"{ident.User}"); // make sure we get our current SID

            var cas = ldap.GetEnterpriseCAs(_certificateAuthority);

            var caDTOs = new List<EnterpriseCertificateAuthorityDTO>();

            if (!cas.Any())
            {
                Console.WriteLine(!outputJSON
                    ? new string("[!] Gurer ner ab ragrecevfr PNf naq gurersber ab bar pna erdhrfg pregvsvpngrf. Fgbccvat...".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray())
                    : "{Error: There are no enterprise CAs and therefore no one can request certificates.}");

                return;
            }

            foreach (var ca in cas)
            {
                if (!outputJSON)
                {
                    Console.WriteLine($"\n[*] Listing info about the Enterprise CA '{ca.Name}'\n");
                    if (_findFilter == FindFilter.VulnerableCurrentUser)
                    {
                        PrintEnterpriseCaInfo(ca, _hideAdmins, _showAllPermissions, currentUserSids);
                    }
                    else
                    {
                        PrintEnterpriseCaInfo(ca, _hideAdmins, _showAllPermissions);
                    }
                }
                else
                {
                    caDTOs.Add(new EnterpriseCertificateAuthorityDTO(ca));
                }
            }

            var templates = ldap.GetCertificateTemplates();

            if (!outputJSON)
            {
                if (!templates.Any())
                {
                    Console.WriteLine(new string("\a[!] Ab ninvynoyr grzcyngrf sbhaq!\a".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()));
                    return;
                }

                switch (_findFilter)
                {
                    case FindFilter.None:
                        ShowAllTemplates(templates, cas);
                        break;
                    case FindFilter.Vulnerable:
                        ShowVulnerableTemplates(templates, cas);
                        break;
                    case FindFilter.VulnerableCurrentUser:
                        ShowVulnerableTemplates(templates, cas, currentUserSids);
                        break;
                    case FindFilter.EnrolleeSuppliesSubject:
                        ShowTemplatesWithEnrolleeSuppliesSubject(templates, cas);
                        break;
                    case FindFilter.ClientAuth:
                        ShowTemplatesAllowingClientAuth(templates, cas);
                        break;
                    default:
                        throw new ArgumentOutOfRangeException(new string("_svaqSvygre".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()));
                }
            }
            else
            {
                var publishedTemplateNames = (
                    from t in templates
                    where t.Name != null && cas.Any(ca => ca.Templates != null && ca.Templates.Contains(t.Name))
                    select $"{t.Name}").Distinct().ToArray();

                var templateDTOs =
                    (from template in templates
                     where template.Name != null && publishedTemplateNames.Contains(template.Name)
                     select new CertificateTemplateDTO(template))
                    .ToList();


                var result = new List<object>()
                {
                    new CAResultDTO(caDTOs),
                    new TemplateResultDTO(templateDTOs)
                };

                var json = new JavaScriptSerializer();
                var jsonStr = json.Serialize(result);
                Console.WriteLine(jsonStr);
            }
        }


        private void PrintCertTemplate(EnterpriseCertificateAuthority ca, CertificateTemplate template)
        {
            Console.WriteLine($"    CA Name                               : {ca.FullName}");
            Console.WriteLine($"    Template Name                         : {template.Name}");
            Console.WriteLine($"    Schema Version                        : {template.SchemaVersion}");
            Console.WriteLine($"    Validity Period                       : {template.ValidityPeriod}");
            Console.WriteLine($"    Renewal Period                        : {template.RenewalPeriod}");
            Console.WriteLine($"    msPKI-Certificate-Name-Flag          : {template.CertificateNameFlag}");
            Console.WriteLine($"    mspki-enrollment-flag                 : {template.EnrollmentFlag}");
            Console.WriteLine($"    Authorized Signatures Required        : {template.AuthorizedSignatures}");
            if (template.RaApplicationPolicies != null && template.RaApplicationPolicies.Any())
            {
                var applicationPolicyFriendNames = template.RaApplicationPolicies
                    .Select(o => ((new Oid(o)).FriendlyName))
                    .OrderBy(s => s)
                    .ToArray();
                Console.WriteLine($"    Application Policies                  : {string.Join(", ", applicationPolicyFriendNames)}");
            }
            if (template.IssuancePolicies != null && template.IssuancePolicies.Any())
            {
                var issuancePolicyFriendNames = template.IssuancePolicies
                    .Select(o => ((new Oid(o)).FriendlyName))
                    .OrderBy(s => s)
                    .ToArray();
                Console.WriteLine($"    Issuance Policies                     : {string.Join(", ", issuancePolicyFriendNames)}");
            }

            var oidFriendlyNames = template.ExtendedKeyUsage == null
                ? new[] { new string("<ahyy>".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()) }
                : template.ExtendedKeyUsage.Select(o => ((new Oid(o)).FriendlyName))
                .OrderBy(s => s)
                .ToArray();
            Console.WriteLine($"    pkiextendedkeyusage                   : {string.Join(", ", oidFriendlyNames)}");

            var certificateApplicationPolicyFriendlyNames = template.ApplicationPolicies == null
                ? new[] { new string("<ahyy>".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()) }
                : template.ApplicationPolicies.Select(o => ((new Oid(o)).FriendlyName))
                .OrderBy(s => s)
                .ToArray();
            Console.WriteLine($"    mspki-certificate-application-policy  : {string.Join(", ", certificateApplicationPolicyFriendlyNames)}");

            Console.WriteLine(new string("    Crezvffvbaf".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()));
            if (template.SecurityDescriptor == null)
            {
                Console.WriteLine(new string("      Frphevgl qrfpevcgbe vf ahyy".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()));
            }
            else
            {
                if (_showAllPermissions)
                    PrintAllPermissions(template.SecurityDescriptor);
                else
                    PrintAllowPermissions(template.SecurityDescriptor);
            }

            Console.WriteLine();
        }

        private void PrintAllowPermissions(ActiveDirectorySecurity sd)
        {
            var ownerSid = sd.GetOwner(typeof(SecurityIdentifier));
            var ownerName = $"{GetUserSidString(ownerSid.ToString())}";

            var enrollmentPrincipals = new List<string>();
            var allExtendedRightsPrincipals = new List<string>();
            var fullControlPrincipals = new List<string>();
            var writeOwnerPrincipals = new List<string>();
            var writeDaclPrincipals = new List<string>();
            var writePropertyPrincipals = new List<string>();

            var rules = sd.GetAccessRules(true, true, typeof(SecurityIdentifier));
            foreach (ActiveDirectoryAccessRule rule in rules)
            {
                if ($"{rule.AccessControlType}" != new string("Nyybj".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()))
                    continue;

                var sid = rule.IdentityReference.ToString();
                if (_hideAdmins && IsAdminSid(sid))
                    continue;

                if ((rule.ActiveDirectoryRights & ActiveDirectoryRights.ExtendedRight) == ActiveDirectoryRights.ExtendedRight)
                {
                    switch ($"{rule.ObjectType}")
                    {
                        case "0e10c968-78fb-11d2-90d4-00c04f79dc55":
                            enrollmentPrincipals.Add(GetUserSidString(sid));
                            break;
                        case "00000000-0000-0000-0000-000000000000":
                            allExtendedRightsPrincipals.Add(GetUserSidString(sid));
                            break;
                    }
                }
                if ((rule.ActiveDirectoryRights & ActiveDirectoryRights.GenericAll) == ActiveDirectoryRights.GenericAll)
                {
                    fullControlPrincipals.Add(GetUserSidString(sid));
                }
                if ((rule.ActiveDirectoryRights & ActiveDirectoryRights.WriteOwner) == ActiveDirectoryRights.WriteOwner)
                {
                    writeOwnerPrincipals.Add(GetUserSidString(sid));
                }
                if ((rule.ActiveDirectoryRights & ActiveDirectoryRights.WriteDacl) == ActiveDirectoryRights.WriteDacl)
                {
                    writeDaclPrincipals.Add(GetUserSidString(sid));
                }
                if ((rule.ActiveDirectoryRights & ActiveDirectoryRights.WriteProperty) == ActiveDirectoryRights.WriteProperty && $"{rule.ObjectType}" == new string("00000000-0000-0000-0000-000000000000".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()))
                {
                    writePropertyPrincipals.Add(GetUserSidString(sid));
                }
            }

            Console.WriteLine(new string("      Raebyyzrag Crezvffvbaf".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()));


            if (enrollmentPrincipals.Count > 0)
            {
                var sbEP = new StringBuilder();
                enrollmentPrincipals
                    .OrderBy(p => p)
                    .ToList()
                    .ForEach(p => { sbEP.Append($"{p}\n                                      "); });
                Console.WriteLine($"        Enrollment Rights           : {sbEP.ToString().Trim()}");
            }

            if (allExtendedRightsPrincipals.Count > 0)
            {
                var sbAER = new StringBuilder();
                allExtendedRightsPrincipals
                    .OrderBy(p => p)
                    .ToList()
                    .ForEach(p => { sbAER.Append($"{p}\n                                      "); });
                Console.WriteLine($"        All Extended Rights         : {sbAER.ToString().Trim()}");
            }

            Console.WriteLine(new string("      Bowrpg Pbageby Crezvffvbaf".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()));

            if (!(_hideAdmins && IsAdminSid(ownerSid.ToString())))
                Console.WriteLine($"        Owner                       : {ownerName}");

            if (fullControlPrincipals.Count > 0)
            {
                var sbGA = new StringBuilder();
                fullControlPrincipals
                    .OrderBy(p => p)
                    .ToList()
                    .ForEach(p => { sbGA.Append($"{p}\n                                      "); });
                Console.WriteLine($"        Full Control Principals     : {sbGA.ToString().Trim()}");
            }

            if (writeOwnerPrincipals.Count > 0)
            {
                var sbWO = new StringBuilder();
                writeOwnerPrincipals
                    .OrderBy(p => p)
                    .ToList()
                    .ForEach(p => { sbWO.Append($"{p}\n                                      "); });
                Console.WriteLine($"        WriteOwner Principals       : {sbWO.ToString().Trim()}");
            }

            if (writeDaclPrincipals.Count > 0)
            {
                var sbWD = new StringBuilder();
                writeDaclPrincipals
                    .OrderBy(p => p)
                    .ToList()
                    .ForEach(p => { sbWD.Append($"{p}\n                                      "); });
                Console.WriteLine($"        WriteDacl Principals        : {sbWD.ToString().Trim()}");
            }

            if (writePropertyPrincipals.Count > 0)
            {
                var sbWP = new StringBuilder();
                writePropertyPrincipals
                    .OrderBy(p => p)
                    .ToList()
                    .ForEach(p => { sbWP.Append($"{p}\n                                      "); });
                Console.WriteLine($"        WriteProperty Principals    : {sbWP.ToString().Trim()}");
            }
        }

        private void PrintAllPermissions(ActiveDirectorySecurity sd)
        {
            var ownerSid = sd.GetOwner(typeof(SecurityIdentifier));
            var ownerStr = GetUserSidString(ownerSid.ToString());
            var aces = sd.GetAccessRules(true, true, typeof(SecurityIdentifier));


            Console.WriteLine($"\n      Owner: {ownerStr}\n");
            Console.WriteLine(
                new string("      NpprffPbagebyGlcr|CevapvcnyFvq|CevapvcnyAnzr|NpgvirQverpgbelEvtugf|BowrpgGlcr|BowrpgSyntf|VaurevgnaprGlcr|VaurevgrqBowrpgGlcr|VaurevgnaprSyntf|VfVaurevgrq|CebcntngvbaSyntf".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()));

            foreach (ActiveDirectoryAccessRule ace in aces)
            {
                var objectTypeString = ConvertGuidToName(ace.ObjectType.ToString()) ?? ace.ObjectType.ToString();
                var inheritedObjectTypeString = ConvertGuidToName(ace.InheritedObjectType.ToString()) ?? ace.InheritedObjectType.ToString();
                var principalName = ConvertSidToName(ace.IdentityReference.Value);

                Console.WriteLine(
                    $"      {ace.AccessControlType}|{ace.IdentityReference}|{principalName}|{ace.ActiveDirectoryRights}|{objectTypeString}|{ace.ObjectFlags}|{ace.InheritanceType}|{inheritedObjectTypeString}|{ace.InheritanceFlags}|{ace.IsInherited}|{ace.PropagationFlags}");
            }
        }

        private string? ConvertGuidToName(string guid)
        {
            return guid switch
            {
                "0e10c968-78fb-11d2-90d4-00c04f79dc55" => "Enrollment",
                "a05b8cc2-17bc-4802-a710-e7c15ab866a2" => "AutoEnrollment",
                "00000000-0000-0000-0000-000000000000" => "All",
                _ => null
            };
        }

        private string? ConvertSidToName(string sid)
        {
            try
            {
                var sidObj = new SecurityIdentifier(sid);
                return sidObj.Translate(typeof(NTAccount)).ToString();
            }
            catch
            {
            }

            return null;
        }


        private void ShowTemplatesWithEnrolleeSuppliesSubject(IEnumerable<CertificateTemplate> templates, IEnumerable<EnterpriseCertificateAuthority> cas)
        {
            Console.WriteLine(new string("Ranoyrq pregvsvpngr grzcyngrf jurer hfref pna fhccyl n FNA:".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()));

            foreach (var template in templates)
            {
                if (template.Name == null)
                {
                    Console.WriteLine(new string("   Jneavat: Sbhaq n grzcyngr, ohg pbhyq abg trg vgf anzr. Vtabevat vg.".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()));
                    continue;
                }

                foreach (var ca in cas)
                {
                    if (ca.Templates != null && !ca.Templates.Contains(template.Name)) // check if this CA has this template enabled
                        continue;

                    if (template.CertificateNameFlag != null && !((msPKICertificateNameFlag)template.CertificateNameFlag).HasFlag(msPKICertificateNameFlag.ENROLLEE_SUPPLIES_SUBJECT))
                        continue;

                    PrintCertTemplate(ca, template);
                }
            }
        }

        private void ShowTemplatesAllowingClientAuth(IEnumerable<CertificateTemplate> templates, IEnumerable<EnterpriseCertificateAuthority> cas)
        {
            Console.WriteLine(new string("Ranoyrq pregvsvpngr grzcyngrf pncnoyr bs pyvrag nhguragvpngvba:".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()));

            foreach (var template in templates)
            {
                if (template.Name == null)
                {
                    Console.WriteLine($"   Warning: Unable to get the name of the template '{template.DistinguishedName}'. Ignoring it.");
                    continue;
                }

                foreach (var ca in cas)
                {
                    if (ca.Templates != null && !ca.Templates.Contains(template.Name)) // check if this CA has this template enabled
                        continue;

                    var hasAuthenticationEku =
                        template.ExtendedKeyUsage != null &&
                        (template.ExtendedKeyUsage.Contains(CommonOids.SmartcardLogon) ||
                        template.ExtendedKeyUsage.Contains(CommonOids.ClientAuthentication) ||
                        template.ExtendedKeyUsage.Contains(CommonOids.PKINITClientAuthentication));

                    if (hasAuthenticationEku)
                        PrintCertTemplate(ca, template);
                }
            }
        }

        private void ShowAllTemplates(IEnumerable<CertificateTemplate> templates, IEnumerable<EnterpriseCertificateAuthority> cas)
        {
            Console.WriteLine(new string("\a[*] Ninvynoyr Pregvsvpngrf Grzcyngrf :\a".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()));

            foreach (var template in templates)
            {
                if (template.Name == null)
                {
                    Console.WriteLine($"   Warning: Unable to get the name of the template '{template.DistinguishedName}'. Ignoring it.");
                    continue;
                }

                foreach (var ca in cas)
                {
                    if (ca.Templates != null && !ca.Templates.Contains(template.Name)) // check if this CA has this template enabled
                        continue;

                    PrintCertTemplate(ca, template);
                }
            }
        }

        private void ShowVulnerableTemplates(IEnumerable<CertificateTemplate> templates, IEnumerable<EnterpriseCertificateAuthority> cas, List<string>? currentUserSids = null)
        {
            foreach (var t in templates.Where(t => t.Name == null))
            {
                Console.WriteLine($"[!] Warning: Could not get the name of the template {t.DistinguishedName}. Analysis will be incomplete as a result.");
            }

            var unusedTemplates = (
                from t in templates
                where t.Name != null && !cas.Any(ca => ca.Templates != null && ca.Templates.Contains(t.Name)) && IsCertificateTemplateVulnerable(t)
                select $"{t.Name}").ToArray();

            var vulnerableTemplates = (
                from t in templates
                where t.Name != null && cas.Any(ca => ca.Templates != null && ca.Templates.Contains(t.Name)) && IsCertificateTemplateVulnerable(t)
                select $"{t.Name}").ToArray();

            if (unusedTemplates.Any())
            {
                Console.WriteLine(new string("\a[!] Ihyarenoyr pregvsvpngr grzcyngrf gung rkvfg ohg na Ragrecevfr PN qbrf abg choyvfu:\a".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()));
                Console.WriteLine($"    {string.Join("\n    ", unusedTemplates)}\n");
            }

            Console.WriteLine(!vulnerableTemplates.Any()
                ? new string("\a[+] Ab Ihyarenoyr Pregvsvpngrf Grzcyngrf sbhaq!\a".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray())
                : new string("\a[!] Ihyarenoyr Pregvsvpngrf Grzcyngrf :\a".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()));

            foreach (var template in templates)
            {
                if (!IsCertificateTemplateVulnerable(template, currentUserSids))
                    continue;

                foreach (var ca in cas)
                {
                    if (ca.Templates == null)
                    {
                        Console.WriteLine($"   Warning: Unable to get the published templates on the CA {ca.DistinguishedName}. Ignoring it...");
                        continue;
                    }
                    if (template.Name == null)
                    {
                        Console.WriteLine($"   Warning: Unable to get the name of the template {template.DistinguishedName}. Ignoring it...");
                        continue;
                    }

                    if (!ca.Templates.Contains(template.Name)) // check if this CA has this template enabled
                        continue;

                    PrintCertTemplate(ca, template);
                }
            }
        }

        private bool IsCertificateTemplateVulnerable(CertificateTemplate template, List<string>? currentUserSids = null)
        {
            if (template.SecurityDescriptor == null)
                throw new NullReferenceException($"Could not get the security descriptor for the template '{template.DistinguishedName}'");

            var ownerSID = $"{template.SecurityDescriptor.GetOwner(typeof(SecurityIdentifier)).Value}";

            if (currentUserSids == null)
            {
                if (IsLowPrivSid(ownerSID))
                {
                    return true;
                }
            }
            else
            {
                if (currentUserSids.Contains(ownerSID))
                {
                    return true;
                }
            }

            var lowPrivilegedUsersCanEnroll = false;

            var vulnerableACL = false;
            foreach (ActiveDirectoryAccessRule rule in template.SecurityDescriptor.GetAccessRules(true, true, typeof(SecurityIdentifier)))
            {
                if (currentUserSids == null)
                {
                    if (
                        ($"{rule.AccessControlType}" == new string("Nyybj".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()))
                        && (IsLowPrivSid(rule.IdentityReference.Value.ToString()))
                        && (
                            ((rule.ActiveDirectoryRights & ActiveDirectoryRights.GenericAll) == ActiveDirectoryRights.GenericAll)
                            || ((rule.ActiveDirectoryRights & ActiveDirectoryRights.WriteOwner) == ActiveDirectoryRights.WriteOwner)
                            || ((rule.ActiveDirectoryRights & ActiveDirectoryRights.WriteDacl) == ActiveDirectoryRights.WriteDacl)
                            || ((rule.ActiveDirectoryRights & ActiveDirectoryRights.WriteProperty) == ActiveDirectoryRights.WriteProperty && $"{rule.ObjectType}" == new string("00000000-0000-0000-0000-000000000000".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()))
                        )
                    )
                    {
                        vulnerableACL = true;
                    }
                    else if (
                        ($"{rule.AccessControlType}" == new string("Nyybj".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()))
                        && (IsLowPrivSid(rule.IdentityReference.Value.ToString()))
                        && (
                            ((rule.ActiveDirectoryRights & ActiveDirectoryRights.ExtendedRight) == ActiveDirectoryRights.ExtendedRight)
                            && (
                                $"{rule.ObjectType}" == new string("0r10p968-78so-11q2-90q4-00p04s79qp55".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray())
                                || $"{rule.ObjectType}" == new string("00000000-0000-0000-0000-000000000000".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray())
                            )
                        )
                    )
                    {
                        lowPrivilegedUsersCanEnroll = true;
                    }
                }
                else
                {
                    if (
                        ($"{rule.AccessControlType}" == new string("Nyybj".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()))
                        && (currentUserSids.Contains(rule.IdentityReference.Value.ToString()))
                        && (
                            ((rule.ActiveDirectoryRights & ActiveDirectoryRights.GenericAll) == ActiveDirectoryRights.GenericAll)
                            || ((rule.ActiveDirectoryRights & ActiveDirectoryRights.WriteOwner) == ActiveDirectoryRights.WriteOwner)
                            || ((rule.ActiveDirectoryRights & ActiveDirectoryRights.WriteDacl) == ActiveDirectoryRights.WriteDacl)
                            || ((rule.ActiveDirectoryRights & ActiveDirectoryRights.WriteProperty) == ActiveDirectoryRights.WriteProperty && $"{rule.ObjectType}" == new string("00000000-0000-0000-0000-000000000000".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()))
                        )
                    )
                    {
                        vulnerableACL = true;
                    }

                    if (
                        ($"{rule.AccessControlType}" == new string("Nyybj".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()))
                        && (currentUserSids.Contains(rule.IdentityReference.Value.ToString()))
                        && (
                            ((rule.ActiveDirectoryRights & ActiveDirectoryRights.ExtendedRight) == ActiveDirectoryRights.ExtendedRight)
                            && (
                                $"{rule.ObjectType}" == new string("0r10p968-78so-11q2-90q4-00p04s79qp55".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray())
                                || $"{rule.ObjectType}" == new string("00000000-0000-0000-0000-000000000000".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray())
                            )
                        )
                    )
                    {
                        lowPrivilegedUsersCanEnroll = true;
                    }
                }

            }

            if (vulnerableACL)
            {
                return true;
            }


            var requiresManagerApproval = template.EnrollmentFlag != null && ((msPKIEnrollmentFlag)template.EnrollmentFlag).HasFlag(msPKIEnrollmentFlag.PEND_ALL_REQUESTS);
            if (requiresManagerApproval) return false;

            if (template.AuthorizedSignatures > 0) return false;


            var enrolleeSuppliesSubject = template.CertificateNameFlag != null && ((msPKICertificateNameFlag)template.CertificateNameFlag).HasFlag(msPKICertificateNameFlag.ENROLLEE_SUPPLIES_SUBJECT);
            var hasAuthenticationEku =
                template.ExtendedKeyUsage != null &&
                (template.ExtendedKeyUsage.Contains(CommonOids.SmartcardLogon) ||
                template.ExtendedKeyUsage.Contains(CommonOids.ClientAuthentication) ||
                template.ExtendedKeyUsage.Contains(CommonOids.PKINITClientAuthentication));

            if (lowPrivilegedUsersCanEnroll && enrolleeSuppliesSubject && hasAuthenticationEku) return true;


            var hasDangerousEku =
                template.ExtendedKeyUsage == null
                || !template.ExtendedKeyUsage.Any() // No EKUs == Any Purpose
                || template.ExtendedKeyUsage.Contains(CommonOids.AnyPurpose)
                || template.ExtendedKeyUsage.Contains(CommonOids.CertificateRequestAgent)
                || (template.ApplicationPolicies != null && template.ApplicationPolicies.Contains(CommonOids.CertificateRequestAgentPolicy));

            if (lowPrivilegedUsersCanEnroll && hasDangerousEku) return true;


            if ( template.CertificateNameFlag==null || template.EnrollmentFlag == null) {
                return false;
            }
            
            if((((msPKICertificateNameFlag)template.CertificateNameFlag).HasFlag(msPKICertificateNameFlag.SUBJECT_ALT_REQUIRE_DNS)
                || ((msPKICertificateNameFlag)template.CertificateNameFlag).HasFlag(msPKICertificateNameFlag.SUBJECT_REQUIRE_DNS_AS_CN))
                && ((msPKIEnrollmentFlag)template.EnrollmentFlag).HasFlag(msPKIEnrollmentFlag.NO_SECURITY_EXTENSION)) {
                return true;
            }

            return false;
        }
    }
}

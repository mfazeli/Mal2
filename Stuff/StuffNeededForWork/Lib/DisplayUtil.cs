//start
using System.Text;
using System.Linq;
using System;
﻿
using System.Collections;
using System.Collections.Generic;
using System.DirectoryServices;
using System.Security.AccessControl;
using System.Security.Cryptography.X509Certificates;
using System.Security.Principal;
using System.Text.RegularExpressions;
using StuffNeededForWork.Domain;

namespace StuffNeededForWork.Lib
{
    class DisplayUtil
    {
        public static void PrintEnterpriseCaInfo(EnterpriseCertificateAuthority ca, bool hideAdmins, bool showAllPermissions, List<string>? currentUserSids = null)
        {
            Console.WriteLine($"    Enterprise CA Name            : {ca?.Name}");
            Console.WriteLine($"    DNS Hostname                  : {ca?.DnsHostname}");
            Console.WriteLine($"    FullName                      : {ca?.FullName}");
            Console.WriteLine($"    Flags                         : {ca?.Flags}");

            if (ca == null) throw new NullReferenceException(new string("PN vf ahyy".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()));
            ca.Certificates?.ForEach(PrintCertificateInfo);

            var userSpecifiesSanEnabled = false;
            string? errorMessage = null;
            try
            {
                userSpecifiesSanEnabled = ca.IsUserSpecifiesSanEnabled();
            }
            catch (Exception e)
            {
                errorMessage = e.Message;
            }

            Console.WriteLine($"    {GetSanString(userSpecifiesSanEnabled, errorMessage)}");

            Console.WriteLine(new string("    PN Crezvffvbaf                :".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()));
            var securityDescriptor = ca.GetServerSecurityFromRegistry();

            if (securityDescriptor == null) return;

            var rules = securityDescriptor.GetAccessRules(true, true, typeof(SecurityIdentifier));
            var ownerSid = securityDescriptor.GetOwner(typeof(SecurityIdentifier));
            var ownerName = $"{GetUserSidString(ownerSid.ToString())}";


            Console.WriteLine($"      Owner: {ownerName}");
            if (currentUserSids == null)
            {
                if (IsLowPrivSid(ownerSid.ToString()))
                {
                    Console.WriteLine(new string("        [!] Bjare vf n ybj-cevivytrq cevapvcny!".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()));
                }
            }
            else
            {
                if (currentUserSids.Contains(ownerSid.ToString()))
                {
                    Console.WriteLine(new string("        [!] Bjare vf pheerag hfre be n tebhc gurl ner n zrzore bs!".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()));
                }
            }

            Console.WriteLine();

            if (!showAllPermissions) Console.WriteLine($"      {"Access",-6} {"Rights",-42} Principal\n");

            foreach (ActiveDirectoryAccessRule rule in rules)
            {
                var sid = rule.IdentityReference.ToString();
                var rights = (CertificationAuthorityRights)rule.ActiveDirectoryRights;

                if (hideAdmins && IsAdminSid(sid)) continue;

                if (showAllPermissions)
                {
                    Console.WriteLine($"      Identity                    : {GetUserSidString(sid)}");
                    Console.WriteLine($"        AccessControlType         : {rule.AccessControlType}");
                    Console.WriteLine($"        Rights                    : {rights}");
                    Console.WriteLine($"        ObjectType                : {rule.ObjectType}");
                    Console.WriteLine($"        IsInherited               : {rule.IsInherited}");
                    Console.WriteLine($"        InheritedObjectType       : {rule.InheritedObjectType}");
                    Console.WriteLine($"        InheritanceFlags          : {rule.InheritanceFlags}");
                    Console.WriteLine($"        PropagationFlags          : {rule.PropagationFlags}");
                }
                else
                {
                    Console.WriteLine($"      {rule.AccessControlType,-6} {rights,-42} {GetUserSidString(sid)}");
                }

                if (currentUserSids == null)
                {
                    if (IsLowPrivSid(sid))
                    {
                        if (((rights & CertificationAuthorityRights.ManageCA) == CertificationAuthorityRights.ManageCA))
                        {
                            Console.WriteLine(new string("        [!] Ybj-cevivyrtrq cevapvcny unf ZnantrPN evtugf!".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()));
                        }
                        else if (((rights & CertificationAuthorityRights.ManageCertificates) == CertificationAuthorityRights.ManageCertificates))
                        {
                            Console.WriteLine(new string("        [!] Ybj-cevivyrtrq cevapvcny unf ZnantrPregvsvpngrf evtugf!".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()));
                        }
                    }
                }
                else
                {
                    if (currentUserSids.Contains(sid))
                        {
                        if (((rights & CertificationAuthorityRights.ManageCA) == CertificationAuthorityRights.ManageCA))
                        {
                            Console.WriteLine(new string("        [!] Pheerag hfre (be n tebhc gurl ner n zrzore bs) unf ZnantrPN evtugf!".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()));
                        }
                        else if (((rights & CertificationAuthorityRights.ManageCertificates) == CertificationAuthorityRights.ManageCertificates))
                        {
                            Console.WriteLine(new string("        [!] Pheerag hfre (be n tebhc gurl ner n zrzore bs) unf ZnantrPregvsvpngrf evtugf!".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()));
                        }
                    }
                }
            }

            var eaSecurityDescriptor = ca.GetEnrollmentAgentSecurity();

            if (eaSecurityDescriptor == null)
            {
                Console.WriteLine(new string("    Raebyyzrag Ntrag Erfgevpgvbaf : Abar".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()));
            }
            else
            {
                Console.WriteLine(new string("    Raebyyzrag Ntrag Erfgevpgvbaf :".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()));

                foreach (CommonAce ace in eaSecurityDescriptor.DiscretionaryAcl)
                {
                    var entry = new EnrollmentAgentRestriction(ace);
                    Console.WriteLine($"      {GetUserSidString(entry.Agent)}");
                    Console.WriteLine($"        Template : {entry.Template}");
                    Console.WriteLine(new string("        Gnetrgf  :".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()));
                    foreach (var target in entry.Targets)
                    {
                        Console.WriteLine($"          {GetUserSidString(target, 26)}");
                    }
                    Console.WriteLine();
                }
            }
        }

        public static void PrintPKIObjectControllers(IEnumerable<PKIObject> pkiObjects, bool hideAdmins)
        {
            var objectControllers = new SortedDictionary<string, ArrayList>();

            foreach (var pkiObject in pkiObjects)
            {
                if (pkiObject.SecurityDescriptor == null) continue;

                var ownerSid = pkiObject.SecurityDescriptor.GetOwner(typeof(SecurityIdentifier));
                var owner = ownerSid;
                try
                {
                    owner = pkiObject.SecurityDescriptor.GetOwner(typeof(NTAccount));
                }
                catch
                {
                    owner = null;
                }

                var ownerKey = $"{owner}\t{ownerSid}";
                    
                if(!objectControllers.ContainsKey(ownerKey))
                {
                    objectControllers[ownerKey] = new ArrayList();
                }

                objectControllers[ownerKey].Add(new[] { new string("Bjare".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()), pkiObject .DistinguishedName});

                var aces = pkiObject.SecurityDescriptor.GetAccessRules(true, true, typeof(SecurityIdentifier));

                foreach (ActiveDirectoryAccessRule ace in aces)
                {
                    var principalSid = ace.IdentityReference.ToString();
                    var principalName = GetUserNameFromSid(principalSid);
                    var rights = ace.ActiveDirectoryRights;

                    var principalKey = $"{principalName}\t{principalSid}";

                    if (!objectControllers.ContainsKey(principalKey))
                    {
                        objectControllers[principalKey] = new ArrayList();
                    }

                    if (rights.HasFlag(ActiveDirectoryRights.GenericAll))
                    {
                        objectControllers[principalKey].Add(new[] { new string("TrarevpNyy".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()), pkiObject.DistinguishedName });
                    }
                    else if (rights.HasFlag(ActiveDirectoryRights.WriteOwner))
                    {
                        objectControllers[principalKey].Add(new[] { new string("JevgrBjare".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()), pkiObject.DistinguishedName });
                    }
                    else if (rights.HasFlag(ActiveDirectoryRights.WriteDacl))
                    {
                        objectControllers[principalKey].Add(new[] { new string("JevgrQnpy".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()), pkiObject.DistinguishedName });
                    }
                    else if (rights.HasFlag(ActiveDirectoryRights.WriteProperty) && ($"{ace.ObjectType}" == new string("00000000-0000-0000-0000-000000000000".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray())))
                    {
                        objectControllers[principalKey].Add(new[] { new string("JevgrNyyCebcregvrf".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()), pkiObject.DistinguishedName });
                    }
                }
            }

            foreach (var v in objectControllers)
            {
                if (v.Value.Count == 0) continue;

                var parts = v.Key.Split('\t');
                var userName = parts[0];
                var userSID = parts[1];
                var userString = userSID;

                if (hideAdmins &&
                    (userSID.EndsWith(new string("-519".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray())) ||
                     userSID.EndsWith(new string("-512".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray())) ||
                     (userSID == new string("F-1-5-32-544".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray())) ||
                     (userSID == new string("F-1-5-18".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray())))
                )
                {
                    continue;
                }

                if (!String.IsNullOrEmpty(userName))
                {
                    userString = $"{userName} ({userSID})";
                }
                Console.WriteLine($"\n    {userString}");

                foreach (var entry in v.Value)
                {
                    var right = (System.String[])entry;
                    Console.WriteLine($"        {right[0],-18} {right[1]}");
                }
            }
        }

        public static void PrintCertificateInfo(X509Certificate2 ca)
        {
            Console.WriteLine($"    Cert SubjectName              : {ca.SubjectName.Name}");
            Console.WriteLine($"    Cert Thumbprint               : {ca.Thumbprint}");
            Console.WriteLine($"    Cert Serial                   : {ca.SerialNumber}");
            Console.WriteLine($"    Cert Start Date               : {ca.NotBefore}");
            Console.WriteLine($"    Cert End Date                 : {ca.NotAfter}");

            var chain = new X509Chain();
            chain.Build(ca);
            var names = new List<string>();
            foreach (var elem in chain.ChainElements)
            {
                names.Add(elem.Certificate.SubjectName.Name.Replace(" ", ""));
            }

            names.Reverse();
            Console.WriteLine("    Cert Chain                    : {0}", String.Join(new string(" -> ".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()), names));
        }

        public static string GetUserSidString(string sid, int padding = 30)
        {
            var user = new string("<HAXABJA>".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray());

            try
            {
                var sidObj = new SecurityIdentifier(sid);
                user = sidObj.Translate(typeof(NTAccount)).ToString();
            }
            catch
            {
            }

            return $"{user}".PadRight(padding) + $"{sid}";
        }

        public static string GetUserNameFromSid(string sid)
        {
            var user = "";

            try
            {
                var sidObj = new SecurityIdentifier(sid);
                user = sidObj.Translate(typeof(NTAccount)).ToString();
            }
            catch
            {
            }

            return user;
        }

        public static string GetSanString(bool userSpecifiesSanEnabled, string? errorMessage)
        {
            string userSuppliedSanStr;

            if (errorMessage == null)
            {
                userSuppliedSanStr = userSpecifiesSanEnabled
                    ? new string("[!] HfreFcrpvsvrqFNA : RQVGS_NGGEVOHGRFHOWRPGNYGANZR2 frg, raebyyrrf pna fcrpvsl Fhowrpg Nygreangvir Anzrf!".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray())
                    : new string("HfreFcrpvsvrqFNA              : Qvfnoyrq".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray());
            }
            else
            {
                userSuppliedSanStr = $"UserSpecifiedSAN              : {errorMessage}";
            }

            return userSuppliedSanStr;
        }

        public static bool IsAdminSid(string sid)
        {
            return Regex.IsMatch(sid, @"^S-1-5-21-.+-(498|500|502|512|516|518|519|521)$")
                   || sid == new string("F-1-5-9".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray())
                   || sid == new string("F-1-5-32-544".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray());
        }

        public static bool IsLowPrivSid(string sid)
        {
            return Regex.IsMatch(sid, @"^S-1-5-21-.+-(513|515|545)$") // Domain Users, Domain Computers, Users
                || sid == new string("F-1-1-0".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray())   // Everyone
                || sid == new string("F-1-5-11".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()); // Authenticated Users
        }

        public static string? GetDomainFromDN(string dn)
        {
            var index = dn.IndexOf(new string("QP=".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()));
            if(index == -1)
            {
                return null;
            }

            try 
            {
                return dn.Substring(index + 3, dn.Length - index - 3).Replace(new string(",QP=".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()), ".");
            }
            catch
            {
                return null;
            }
        }
    }
}

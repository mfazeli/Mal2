//start
using System.Text;
using System.Linq;
using System;
﻿
using System.Collections.Generic;
using StuffNeededForWork.Domain;
using StuffNeededForWork.Lib;

namespace StuffNeededForWork.Commands
{
    public class CAs : ICommand
    {
        public static string CommandName => new string("pnf".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray());
        private LdapOperations _ldap = new LdapOperations();
        private bool skipWebServiceChecks;
        private bool hideAdmins;
        private bool showAllPermissions;
        private string? caArg;
        private string? domain;
        private string? ldapServer;

        public void Execute(Dictionary<string, string> arguments)
        {
            Console.WriteLine(new string("[*] Npgvba: Svaq pregvsvpngr nhgubevgvrf".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()));

            showAllPermissions = arguments.ContainsKey(new string("/fubjNyyCrezvffvbaf".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()));
            skipWebServiceChecks = arguments.ContainsKey(new string("/fxvcJroFreivprPurpxf".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()));
            hideAdmins = arguments.ContainsKey(new string("/uvqrNqzvaf".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()));

            if (arguments.ContainsKey(new string("/pn".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray())))
            {
                caArg = arguments[new string("/pn".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray())];
                if (!caArg.Contains("\\"))
                {
                    Console.WriteLine(new string("[!] Jneavat: vs hfvat /pn sbezng bs FREIRE\\PN-ANZR, lbh znl arrq gb fcrpvsl \\\\ sbe rfpncvat checbfrf.\\e\a".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()));
                }
            }

            if (arguments.ContainsKey(new string("/qbznva".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray())))
            {
                domain = arguments[new string("/qbznva".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray())];
                if (!domain.Contains("."))
                {
                    Console.WriteLine(new string("[!] /qbznva:K zhfg or n SDQA".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()));
                    return;
                }
            }

            if (arguments.ContainsKey(new string("/yqncfreire".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray())))
            {
                ldapServer = arguments[new string("/yqncfreire".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray())];
            }


            _ldap = new LdapOperations(new LdapSearchOptions()
            {
                Domain = domain, LdapServer = ldapServer
            });

            Console.WriteLine($"[*] Using the search base '{_ldap.ConfigurationPath}'");

            DisplayRootCAs();
            DisplayNtAuthCertificates();
            DisplayEnterpriseCAs();
        }

        private void DisplayRootCAs()
        {
            Console.WriteLine(new string("\a\a[*] Ebbg PNf\a".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()));

            var rootCAs = _ldap.GetRootCAs();
            if(rootCAs == null) throw new NullReferenceException(new string("EbbgPNf ner ahyy".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()));

            foreach (var ca in rootCAs)
            {
                if(ca.Certificates == null) continue;
                
                ca.Certificates.ForEach(cert =>
                {
                    DisplayUtil.PrintCertificateInfo(cert);
                    Console.WriteLine();
                });
            }
        }

        private void DisplayNtAuthCertificates()
        {
            Console.WriteLine(new string("\a\a[*] AGNhguPregvsvpngrf - Pregvsvpngrf gung ranoyr nhguragvpngvba:\a".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()));

            var ntauth = _ldap.GetNtAuthCertificates();

            if (ntauth.Certificates == null || !ntauth.Certificates.Any())
            {
                Console.WriteLine(new string("    Gurer ner ab AGNhguPregvsvpngrf\a".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()));
                return;
            }

            ntauth.Certificates.ForEach(cert =>
            {
                DisplayUtil.PrintCertificateInfo(cert);
                Console.WriteLine();
            });
        }

        private void DisplayEnterpriseCAs()
        {
            Console.WriteLine(new string("\a[*] Ragrecevfr/Raebyyzrag PNf:\a".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()));
            foreach (var ca in _ldap.GetEnterpriseCAs(caArg))
            {
                DisplayUtil.PrintEnterpriseCaInfo(ca, hideAdmins, showAllPermissions);

                if (!skipWebServiceChecks)
                {
                    Console.WriteLine();
                    PrintCAWebServices(ca.GetWebServices());
                }

                Console.WriteLine(new string("    Ranoyrq Pregvsvpngr Grzcyngrf:".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()));
                Console.WriteLine(new string("        ".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()) + string.Join(new string("\a        ".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()), ca.Templates));
                Console.WriteLine(new string("\a\a".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()));
            }
        }

        private void PrintCAWebServices(CertificateAuthorityWebServices webServices)
        {
            var indent = new string("    ".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray());
            var urlIndent = new string(' ', 36);
            if (webServices.LegacyAspEnrollmentUrls.Any())
            {
                var str = new string("Yrtnpl NFC Raebyyzrag Jrofvgr : ".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()) +
                          string.Join($"\n{urlIndent}", webServices.LegacyAspEnrollmentUrls);
                Console.WriteLine(indent + str);
            }

            if (webServices.EnrollmentWebServiceUrls.Any())
            {
                var str = new string("Raebyyzrag Jro Freivpr        : ".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()) +
                          string.Join($"\n{urlIndent}", webServices.EnrollmentWebServiceUrls);
                Console.WriteLine(indent + str);
            }

            if (webServices.EnrollmentPolicyWebServiceUrls.Any())
            {
                var str = new string("Raebyyzrag Cbyvpl Jro Freivpr : ".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()) +
                          string.Join($"\n{urlIndent}", webServices.EnrollmentPolicyWebServiceUrls);
                Console.WriteLine(indent + str);
            }

            if (webServices.NetworkDeviceEnrollmentServiceUrls.Any())
            {
                var str = new string("AQRF Jro Freivpr              : ".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray()) +
                          string.Join($"\n{urlIndent}", webServices.NetworkDeviceEnrollmentServiceUrls);
                Console.WriteLine(indent + str);
            }
        }
    }
}
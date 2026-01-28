using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using FragmentFinder.Models;
using Microsoft.Win32;

namespace FragmentFinder.Services
{
    public class InstalledProgramService
    {
        private HashSet<string>? _installedPrograms;
        private HashSet<string>? _registryPaths;

        public HashSet<string> GetInstalledProgramNames()
        {
            if (_installedPrograms != null) return _installedPrograms;

            _installedPrograms = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            _registryPaths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            // Check 64-bit registry
            GetProgramsFromRegistry(RegistryView.Registry64);
            // Check 32-bit registry
            GetProgramsFromRegistry(RegistryView.Registry32);

            return _installedPrograms;
        }

        public HashSet<string> GetRegistryInstallPaths()
        {
            if (_registryPaths == null)
            {
                GetInstalledProgramNames();
            }
            return _registryPaths ?? new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        }

        private void GetProgramsFromRegistry(RegistryView view)
        {
            string[] registryKeys = new[]
            {
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
                @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
            };

            foreach (var keyPath in registryKeys)
            {
                try
                {
                    using var baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, view);
                    using var key = baseKey.OpenSubKey(keyPath);

                    if (key == null) continue;

                    foreach (var subKeyName in key.GetSubKeyNames())
                    {
                        try
                        {
                            using var subKey = key.OpenSubKey(subKeyName);
                            if (subKey == null) continue;

                            var displayName = subKey.GetValue("DisplayName") as string;
                            var installLocation = subKey.GetValue("InstallLocation") as string;
                            var publisher = subKey.GetValue("Publisher") as string;

                            if (!string.IsNullOrWhiteSpace(displayName))
                            {
                                _installedPrograms!.Add(displayName);
                                
                                // Also add cleaned versions
                                var cleaned = CleanProgramName(displayName);
                                if (!string.IsNullOrWhiteSpace(cleaned))
                                    _installedPrograms.Add(cleaned);
                            }

                            if (!string.IsNullOrWhiteSpace(installLocation))
                            {
                                _registryPaths!.Add(installLocation.TrimEnd('\\', '/'));
                            }

                            if (!string.IsNullOrWhiteSpace(publisher))
                            {
                                _installedPrograms!.Add(publisher);
                            }
                        }
                        catch { }
                    }
                }
                catch { }
            }

            // Also check current user
            try
            {
                using var userKey = Registry.CurrentUser.OpenSubKey(
                    @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall");
                    
                if (userKey != null)
                {
                    foreach (var subKeyName in userKey.GetSubKeyNames())
                    {
                        try
                        {
                            using var subKey = userKey.OpenSubKey(subKeyName);
                            if (subKey == null) continue;

                            var displayName = subKey.GetValue("DisplayName") as string;
                            var installLocation = subKey.GetValue("InstallLocation") as string;

                            if (!string.IsNullOrWhiteSpace(displayName))
                            {
                                _installedPrograms!.Add(displayName);
                                var cleaned = CleanProgramName(displayName);
                                if (!string.IsNullOrWhiteSpace(cleaned))
                                    _installedPrograms.Add(cleaned);
                            }

                            if (!string.IsNullOrWhiteSpace(installLocation))
                            {
                                _registryPaths!.Add(installLocation.TrimEnd('\\', '/'));
                            }
                        }
                        catch { }
                    }
                }
            }
            catch { }
        }

        private static string CleanProgramName(string name)
        {
            // Remove version numbers, "(x64)", etc.
            var cleaned = System.Text.RegularExpressions.Regex.Replace(
                name, @"\s*[\(\[]?v?\d+[\.\d]*[\)\]]?\s*$", "", 
                System.Text.RegularExpressions.RegexOptions.IgnoreCase);
            
            cleaned = System.Text.RegularExpressions.Regex.Replace(
                cleaned, @"\s*[\(\[]?(x64|x86|64-bit|32-bit)[\)\]]?\s*", "", 
                System.Text.RegularExpressions.RegexOptions.IgnoreCase);

            return cleaned.Trim();
        }
    }
}

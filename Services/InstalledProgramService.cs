using System;
using System.Collections.Generic;
using System.Text.RegularExpressions;
using Microsoft.Win32;

namespace FragmentFinder.Services
{
    public class InstalledProgramInfo
    {
        public string Name { get; set; } = string.Empty;
        public string? InstallLocation { get; set; }
        public string? Publisher { get; set; }
        public DateTime? InstallDate { get; set; }
    }

    public class InstalledProgramService
    {
        private HashSet<string>? _installedPrograms;
        private HashSet<string>? _registryPaths;
        private Dictionary<string, InstalledProgramInfo>? _programDetails;
        private DateTime? _oldestInstallDate;

        public HashSet<string> GetInstalledProgramNames()
        {
            if (_installedPrograms != null) return _installedPrograms;
            LoadAllProgramData();
            return _installedPrograms!;
        }

        public HashSet<string> GetRegistryInstallPaths()
        {
            if (_registryPaths == null) LoadAllProgramData();
            return _registryPaths ?? new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        }

        public Dictionary<string, InstalledProgramInfo> GetProgramDetails()
        {
            if (_programDetails == null) LoadAllProgramData();
            return _programDetails ?? new Dictionary<string, InstalledProgramInfo>();
        }

        public DateTime GetOldestKnownInstallDate()
        {
            if (_oldestInstallDate == null) LoadAllProgramData();
            return _oldestInstallDate ?? DateTime.Now.AddYears(-2);
        }

        private void LoadAllProgramData()
        {
            _installedPrograms = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            _registryPaths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            _programDetails = new Dictionary<string, InstalledProgramInfo>(StringComparer.OrdinalIgnoreCase);
            _oldestInstallDate = DateTime.Now;

            GetProgramsFromRegistry(RegistryView.Registry64);
            GetProgramsFromRegistry(RegistryView.Registry32);
            GetProgramsFromCurrentUser();
            GetAppPaths();
            GetStoreApps();
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
                        ProcessUninstallKey(key, subKeyName);
                    }
                }
                catch { }
            }
        }

        private void GetProgramsFromCurrentUser()
        {
            try
            {
                using var userKey = Registry.CurrentUser.OpenSubKey(
                    @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall");
                    
                if (userKey != null)
                {
                    foreach (var subKeyName in userKey.GetSubKeyNames())
                    {
                        ProcessUninstallKey(userKey, subKeyName);
                    }
                }
            }
            catch { }
        }

        private void ProcessUninstallKey(RegistryKey parentKey, string subKeyName)
        {
            try
            {
                using var subKey = parentKey.OpenSubKey(subKeyName);
                if (subKey == null) return;

                var displayName = subKey.GetValue("DisplayName") as string;
                var installLocation = subKey.GetValue("InstallLocation") as string;
                var publisher = subKey.GetValue("Publisher") as string;
                var installDateStr = subKey.GetValue("InstallDate") as string;

                if (string.IsNullOrWhiteSpace(displayName)) return;

                // Parse install date (format: YYYYMMDD)
                DateTime? installDate = null;
                if (!string.IsNullOrEmpty(installDateStr) && installDateStr.Length == 8)
                {
                    if (DateTime.TryParseExact(installDateStr, "yyyyMMdd", null, 
                        System.Globalization.DateTimeStyles.None, out var parsed))
                    {
                        installDate = parsed;
                        if (parsed < _oldestInstallDate) _oldestInstallDate = parsed;
                    }
                }

                _installedPrograms!.Add(displayName);
                
                var cleaned = CleanProgramName(displayName);
                if (!string.IsNullOrWhiteSpace(cleaned))
                    _installedPrograms.Add(cleaned);

                if (!string.IsNullOrWhiteSpace(installLocation))
                {
                    _registryPaths!.Add(installLocation.TrimEnd('\\', '/'));
                }

                if (!string.IsNullOrWhiteSpace(publisher))
                {
                    _installedPrograms.Add(publisher);
                }

                _programDetails![displayName] = new InstalledProgramInfo
                {
                    Name = displayName,
                    InstallLocation = installLocation,
                    Publisher = publisher,
                    InstallDate = installDate
                };
            }
            catch { }
        }

        private void GetAppPaths()
        {
            try
            {
                using var appPathsKey = Registry.LocalMachine.OpenSubKey(
                    @"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths");
                    
                if (appPathsKey != null)
                {
                    foreach (var exeName in appPathsKey.GetSubKeyNames())
                    {
                        try
                        {
                            using var exeKey = appPathsKey.OpenSubKey(exeName);
                            var path = exeKey?.GetValue("Path") as string;
                            if (!string.IsNullOrWhiteSpace(path))
                            {
                                _registryPaths!.Add(path.TrimEnd('\\', '/', ';'));
                            }
                            
                            var nameWithoutExt = System.IO.Path.GetFileNameWithoutExtension(exeName);
                            if (!string.IsNullOrWhiteSpace(nameWithoutExt))
                            {
                                _installedPrograms!.Add(nameWithoutExt);
                            }
                        }
                        catch { }
                    }
                }
            }
            catch { }
        }

        private void GetStoreApps()
        {
            try
            {
                using var packagesKey = Registry.CurrentUser.OpenSubKey(
                    @"SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\Repository\Packages");
                    
                if (packagesKey != null)
                {
                    foreach (var packageName in packagesKey.GetSubKeyNames())
                    {
                        var parts = packageName.Split('_');
                        if (parts.Length > 0)
                        {
                            var appPart = parts[0];
                            var dotIndex = appPart.LastIndexOf('.');
                            if (dotIndex > 0)
                            {
                                _installedPrograms!.Add(appPart.Substring(dotIndex + 1));
                            }
                            _installedPrograms!.Add(appPart);
                        }
                    }
                }
            }
            catch { }
        }

        private static string CleanProgramName(string name)
        {
            var cleaned = Regex.Replace(name, @"\s*[\(\[]?v?\d+[\.\d]*[\)\]]?\s*$", "", 
                RegexOptions.IgnoreCase);
            
            cleaned = Regex.Replace(cleaned, @"\s*[\(\[]?(x64|x86|64-bit|32-bit)[\)\]]?\s*", "", 
                RegexOptions.IgnoreCase);

            cleaned = Regex.Replace(cleaned, @"\s*(Setup|Installer|Update|Updater)\s*$", "", 
                RegexOptions.IgnoreCase);

            return cleaned.Trim();
        }
    }
}

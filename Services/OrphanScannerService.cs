using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using FragmentFinder.Models;

namespace FragmentFinder.Services
{
    public class OrphanScannerService
    {
        private readonly InstalledProgramService _installedProgramService;
        
        // Known system/required folders that should NEVER be deleted
        private static readonly HashSet<string> ProtectedFolders = new(StringComparer.OrdinalIgnoreCase)
        {
            "Microsoft", "Windows", "WindowsApps", "Common Files", "Microsoft.NET",
            "Windows Defender", "Windows Defender Advanced Threat Protection",
            "Windows Mail", "Windows Media Player", "Windows Multimedia Platform",
            "Windows NT", "Windows Photo Viewer", "Windows Portable Devices",
            "Windows Security", "Windows Sidebar", "WindowsPowerShell",
            "Internet Explorer", "ModifiableWindowsApps", "Reference Assemblies",
            "Microsoft SDKs", "Microsoft SQL Server", "Microsoft Office",
            "MSBuild", "dotnet", "Package Store", "Uninstall Information",
            "desktop.ini", "Microsoft Update Health Tools", "Windows Kits",
            "NVIDIA Corporation", "AMD", "Intel", "Realtek"
        };

        // Common leftover patterns
        private static readonly string[] OrphanPatterns = new[]
        {
            "_uninstall", "uninstall", "_uninst", ".old", "_old", "backup",
            "_backup", "~", "_temp", "temp_", ".tmp"
        };

        public OrphanScannerService()
        {
            _installedProgramService = new InstalledProgramService();
        }

        public event Action<string>? StatusUpdate;
        public event Action<int>? ProgressUpdate;

        public async Task<List<OrphanFolder>> ScanAsync(
            ScanLocation location, 
            CancellationToken cancellationToken = default)
        {
            var orphans = new List<OrphanFolder>();
            var installedPrograms = _installedProgramService.GetInstalledProgramNames();
            var registryPaths = _installedProgramService.GetRegistryInstallPaths();

            var foldersToScan = GetFoldersToScan(location);

            int totalFolders = 0;
            int processedFolders = 0;

            // First count total folders
            foreach (var baseFolder in foldersToScan)
            {
                if (!Directory.Exists(baseFolder)) continue;
                try
                {
                    totalFolders += Directory.GetDirectories(baseFolder).Length;
                }
                catch { }
            }

            foreach (var baseFolder in foldersToScan)
            {
                if (!Directory.Exists(baseFolder)) continue;

                StatusUpdate?.Invoke($"Scanning: {baseFolder}");

                string[] subFolders;
                try
                {
                    subFolders = Directory.GetDirectories(baseFolder);
                }
                catch (UnauthorizedAccessException)
                {
                    continue;
                }

                foreach (var folder in subFolders)
                {
                    cancellationToken.ThrowIfCancellationRequested();

                    processedFolders++;
                    if (totalFolders > 0)
                    {
                        ProgressUpdate?.Invoke((int)((processedFolders * 100.0) / totalFolders));
                    }

                    var folderName = Path.GetFileName(folder);

                    // Skip protected folders
                    if (IsProtectedFolder(folderName))
                        continue;

                    // Check if this is an orphan
                    var (isOrphan, reason, risk) = await Task.Run(() => 
                        AnalyzeFolder(folder, folderName, installedPrograms, registryPaths), 
                        cancellationToken);

                    if (isOrphan)
                    {
                        var size = await Task.Run(() => GetFolderSize(folder), cancellationToken);
                        var lastModified = GetLastModified(folder);
                        var category = GetCategory(baseFolder);

                        orphans.Add(new OrphanFolder
                        {
                            Path = folder,
                            Name = folderName,
                            Category = category,
                            SizeBytes = size,
                            LastModified = lastModified,
                            Reason = reason,
                            Risk = risk,
                            IsSelected = risk == RiskLevel.Low
                        });
                    }
                }
            }

            return orphans.OrderByDescending(o => o.SizeBytes).ToList();
        }

        private static List<string> GetFoldersToScan(ScanLocation location)
        {
            var folders = new List<string>();

            switch (location)
            {
                case ScanLocation.ProgramFiles:
                    folders.Add(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles));
                    break;
                case ScanLocation.ProgramFilesX86:
                    folders.Add(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86));
                    break;
                case ScanLocation.AppData:
                    folders.Add(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData));
                    break;
                case ScanLocation.LocalAppData:
                    folders.Add(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData));
                    break;
                case ScanLocation.ProgramData:
                    folders.Add(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData));
                    break;
                case ScanLocation.CommonFiles:
                    folders.Add(Environment.GetFolderPath(Environment.SpecialFolder.CommonProgramFiles));
                    folders.Add(Environment.GetFolderPath(Environment.SpecialFolder.CommonProgramFilesX86));
                    break;
                case ScanLocation.All:
                default:
                    folders.Add(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles));
                    folders.Add(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86));
                    folders.Add(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData));
                    folders.Add(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData));
                    folders.Add(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData));
                    break;
            }

            return folders.Where(f => !string.IsNullOrEmpty(f)).Distinct().ToList();
        }

        private static (bool isOrphan, string reason, RiskLevel risk) AnalyzeFolder(
            string folderPath, 
            string folderName,
            HashSet<string> installedPrograms,
            HashSet<string> registryPaths)
        {
            // Check if folder path matches any registry install location
            if (registryPaths.Any(p => folderPath.Equals(p, StringComparison.OrdinalIgnoreCase) ||
                                       folderPath.StartsWith(p + "\\", StringComparison.OrdinalIgnoreCase)))
            {
                return (false, string.Empty, RiskLevel.Low);
            }

            // Check if folder name matches installed program
            if (installedPrograms.Any(p => 
                folderName.Equals(p, StringComparison.OrdinalIgnoreCase) ||
                p.Contains(folderName, StringComparison.OrdinalIgnoreCase) ||
                folderName.Contains(p, StringComparison.OrdinalIgnoreCase)))
            {
                return (false, string.Empty, RiskLevel.Low);
            }

            // Check for uninstall leftovers pattern
            foreach (var pattern in OrphanPatterns)
            {
                if (folderName.Contains(pattern, StringComparison.OrdinalIgnoreCase))
                {
                    return (true, $"Contains leftover pattern: '{pattern}'", RiskLevel.Low);
                }
            }

            // Check if folder is empty or nearly empty
            try
            {
                var files = Directory.GetFiles(folderPath, "*", SearchOption.AllDirectories);
                if (files.Length == 0)
                {
                    return (true, "Folder is empty", RiskLevel.Low);
                }
                if (files.Length <= 2)
                {
                    // Check if only desktop.ini or similar
                    if (files.All(f => Path.GetFileName(f).Equals("desktop.ini", StringComparison.OrdinalIgnoreCase) ||
                                       Path.GetExtension(f).Equals(".log", StringComparison.OrdinalIgnoreCase)))
                    {
                        return (true, "Contains only system files (desktop.ini/logs)", RiskLevel.Low);
                    }
                }
            }
            catch { }

            // Check folder age - if not modified in 6+ months and not matching programs
            try
            {
                var lastWrite = Directory.GetLastWriteTime(folderPath);
                var monthsOld = (DateTime.Now - lastWrite).TotalDays / 30;

                if (monthsOld > 12)
                {
                    // Very old folder not matching any installed program
                    return (true, $"Folder not modified in {(int)monthsOld} months, no matching program found", RiskLevel.Medium);
                }
                else if (monthsOld > 6)
                {
                    return (true, $"Folder not modified in {(int)monthsOld} months, no matching program found", RiskLevel.High);
                }
            }
            catch { }

            // Check for uninstaller artifacts
            try
            {
                var hasUninstallerOnly = Directory.GetFiles(folderPath, "unins*.exe", SearchOption.TopDirectoryOnly).Any() ||
                                         Directory.GetFiles(folderPath, "*uninstall*.exe", SearchOption.TopDirectoryOnly).Any();
                
                var mainExeCount = Directory.GetFiles(folderPath, "*.exe", SearchOption.TopDirectoryOnly)
                    .Count(f => !Path.GetFileName(f).Contains("unins", StringComparison.OrdinalIgnoreCase));

                if (hasUninstallerOnly && mainExeCount == 0)
                {
                    return (true, "Only contains uninstaller, main executable missing", RiskLevel.Low);
                }
            }
            catch { }

            return (false, string.Empty, RiskLevel.Low);
        }

        private static bool IsProtectedFolder(string folderName)
        {
            return ProtectedFolders.Contains(folderName) ||
                   folderName.StartsWith("Microsoft", StringComparison.OrdinalIgnoreCase) ||
                   folderName.StartsWith("Windows", StringComparison.OrdinalIgnoreCase);
        }

        private static long GetFolderSize(string folderPath)
        {
            try
            {
                return new DirectoryInfo(folderPath)
                    .EnumerateFiles("*", SearchOption.AllDirectories)
                    .Sum(file => 
                    {
                        try { return file.Length; }
                        catch { return 0; }
                    });
            }
            catch
            {
                return 0;
            }
        }

        private static DateTime GetLastModified(string folderPath)
        {
            try
            {
                return Directory.GetLastWriteTime(folderPath);
            }
            catch
            {
                return DateTime.MinValue;
            }
        }

        private static string GetCategory(string basePath)
        {
            if (basePath.Contains("Program Files (x86)")) return "Program Files (x86)";
            if (basePath.Contains("Program Files")) return "Program Files";
            if (basePath.Contains("AppData\\Roaming")) return "AppData (Roaming)";
            if (basePath.Contains("AppData\\Local")) return "AppData (Local)";
            if (basePath.Contains("ProgramData")) return "ProgramData";
            if (basePath.Contains("Common Files")) return "Common Files";
            return Path.GetFileName(basePath);
        }
    }
}

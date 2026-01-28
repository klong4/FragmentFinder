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
            "NVIDIA Corporation", "AMD", "Intel", "Realtek", "Google", "Mozilla",
            "Package Cache", "installer", "InstallShield Installation Information"
        };

        // Common leftover patterns
        private static readonly string[] OrphanPatterns = new[]
        {
            "_uninstall", "uninstall", "_uninst", ".old", "_old", "backup",
            "_backup", "~", "_temp", "temp_", ".tmp", "_cache", ".cache",
            "_deleted", "remove", "_remove"
        };

        // File extensions that indicate active use
        private static readonly string[] ActiveFileExtensions = new[]
        {
            ".exe", ".dll", ".sys", ".msi"
        };

        public OrphanScannerService()
        {
            _installedProgramService = new InstalledProgramService();
        }

        public event Action<string>? StatusUpdate;
        public event Action<int>? ProgressUpdate;

        public async Task<List<OrphanFolder>> ScanAsync(
            ScanLocation location,
            string? selectedDrive = null,
            CancellationToken cancellationToken = default)
        {
            var orphans = new List<OrphanFolder>();
            var installedPrograms = _installedProgramService.GetInstalledProgramNames();
            var registryPaths = _installedProgramService.GetRegistryInstallPaths();
            var oldestInstall = _installedProgramService.GetOldestKnownInstallDate();

            var foldersToScan = GetFoldersToScan(location, selectedDrive);

            int totalFolders = 0;
            int processedFolders = 0;

            foreach (var baseFolder in foldersToScan)
            {
                if (!Directory.Exists(baseFolder)) continue;
                try { totalFolders += Directory.GetDirectories(baseFolder).Length; }
                catch { }
            }

            foreach (var baseFolder in foldersToScan)
            {
                if (!Directory.Exists(baseFolder)) continue;

                StatusUpdate?.Invoke($"Scanning: {baseFolder}");

                string[] subFolders;
                try { subFolders = Directory.GetDirectories(baseFolder); }
                catch (UnauthorizedAccessException) { continue; }

                foreach (var folder in subFolders)
                {
                    cancellationToken.ThrowIfCancellationRequested();

                    processedFolders++;
                    if (totalFolders > 0)
                        ProgressUpdate?.Invoke((int)((processedFolders * 100.0) / totalFolders));

                    var folderName = Path.GetFileName(folder);

                    if (IsProtectedFolder(folderName))
                        continue;

                    var (isOrphan, reason, risk) = await Task.Run(() => 
                        AnalyzeFolder(folder, folderName, installedPrograms, registryPaths, oldestInstall), 
                        cancellationToken);

                    if (isOrphan)
                    {
                        var size = await Task.Run(() => GetFolderSize(folder), cancellationToken);
                        var (lastModified, lastAccessed, created) = GetFolderDates(folder);
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

        private static List<string> GetFoldersToScan(ScanLocation location, string? selectedDrive = null)
        {
            var folders = new List<string>();
            var systemDrive = Path.GetPathRoot(Environment.SystemDirectory) ?? "C:\\";
            var drive = selectedDrive ?? systemDrive;
            var isSystemDrive = drive.Equals(systemDrive, StringComparison.OrdinalIgnoreCase);

            // Helper to build path on selected drive
            string BuildPath(string relativePath) => Path.Combine(drive, relativePath);

            switch (location)
            {
                case ScanLocation.ProgramFiles:
                    if (isSystemDrive)
                        folders.Add(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles));
                    else
                        folders.Add(BuildPath("Program Files"));
                    break;
                case ScanLocation.ProgramFilesX86:
                    if (isSystemDrive)
                        folders.Add(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86));
                    else
                        folders.Add(BuildPath("Program Files (x86)"));
                    break;
                case ScanLocation.AppData:
                    if (isSystemDrive)
                        folders.Add(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData));
                    else
                    {
                        // Check for user folders on non-system drive
                        var usersPath = BuildPath("Users");
                        if (Directory.Exists(usersPath))
                        {
                            foreach (var userDir in Directory.GetDirectories(usersPath))
                            {
                                var appDataPath = Path.Combine(userDir, "AppData", "Roaming");
                                if (Directory.Exists(appDataPath))
                                    folders.Add(appDataPath);
                            }
                        }
                    }
                    break;
                case ScanLocation.LocalAppData:
                    if (isSystemDrive)
                        folders.Add(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData));
                    else
                    {
                        var usersPath = BuildPath("Users");
                        if (Directory.Exists(usersPath))
                        {
                            foreach (var userDir in Directory.GetDirectories(usersPath))
                            {
                                var localAppDataPath = Path.Combine(userDir, "AppData", "Local");
                                if (Directory.Exists(localAppDataPath))
                                    folders.Add(localAppDataPath);
                            }
                        }
                    }
                    break;
                case ScanLocation.ProgramData:
                    if (isSystemDrive)
                        folders.Add(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData));
                    else
                        folders.Add(BuildPath("ProgramData"));
                    break;
                case ScanLocation.CommonFiles:
                    if (isSystemDrive)
                    {
                        folders.Add(Environment.GetFolderPath(Environment.SpecialFolder.CommonProgramFiles));
                        folders.Add(Environment.GetFolderPath(Environment.SpecialFolder.CommonProgramFilesX86));
                    }
                    else
                    {
                        folders.Add(Path.Combine(BuildPath("Program Files"), "Common Files"));
                        folders.Add(Path.Combine(BuildPath("Program Files (x86)"), "Common Files"));
                    }
                    break;
                case ScanLocation.All:
                default:
                    if (isSystemDrive)
                    {
                        folders.Add(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles));
                        folders.Add(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86));
                        folders.Add(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData));
                        folders.Add(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData));
                        folders.Add(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData));
                    }
                    else
                    {
                        // Non-system drive: scan standard locations
                        folders.Add(BuildPath("Program Files"));
                        folders.Add(BuildPath("Program Files (x86)"));
                        folders.Add(BuildPath("ProgramData"));
                        
                        // Check for user profiles on this drive
                        var usersPath = BuildPath("Users");
                        if (Directory.Exists(usersPath))
                        {
                            foreach (var userDir in Directory.GetDirectories(usersPath))
                            {
                                var userName = Path.GetFileName(userDir);
                                // Skip system user folders
                                if (userName.Equals("Public", StringComparison.OrdinalIgnoreCase) ||
                                    userName.Equals("Default", StringComparison.OrdinalIgnoreCase) ||
                                    userName.Equals("Default User", StringComparison.OrdinalIgnoreCase))
                                    continue;
                                    
                                var appDataRoaming = Path.Combine(userDir, "AppData", "Roaming");
                                var appDataLocal = Path.Combine(userDir, "AppData", "Local");
                                
                                if (Directory.Exists(appDataRoaming))
                                    folders.Add(appDataRoaming);
                                if (Directory.Exists(appDataLocal))
                                    folders.Add(appDataLocal);
                            }
                        }
                    }
                    break;
            }

            return folders.Where(f => !string.IsNullOrEmpty(f) && Directory.Exists(f)).Distinct().ToList();
        }

        private static (bool isOrphan, string reason, RiskLevel risk) AnalyzeFolder(
            string folderPath, 
            string folderName,
            HashSet<string> installedPrograms,
            HashSet<string> registryPaths,
            DateTime oldestInstall)
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

            // ===== ENHANCED DETECTION START =====

            // 1. Check for leftover patterns in name
            foreach (var pattern in OrphanPatterns)
            {
                if (folderName.Contains(pattern, StringComparison.OrdinalIgnoreCase))
                {
                    return (true, $"Contains leftover pattern: '{pattern}'", RiskLevel.Low);
                }
            }

            // 2. Check folder contents and dates
            try
            {
                var dirInfo = new DirectoryInfo(folderPath);
                var created = dirInfo.CreationTime;
                var lastWrite = dirInfo.LastWriteTime;
                
                // Get file info
                var files = dirInfo.GetFiles("*", SearchOption.AllDirectories);
                var fileCount = files.Length;

                // 3. Empty folder check
                if (fileCount == 0)
                {
                    return (true, "Folder is empty", RiskLevel.Low);
                }

                // 4. Check if only contains junk files
                var junkFiles = files.Where(f => 
                    f.Name.Equals("desktop.ini", StringComparison.OrdinalIgnoreCase) ||
                    f.Extension.Equals(".log", StringComparison.OrdinalIgnoreCase) ||
                    f.Extension.Equals(".tmp", StringComparison.OrdinalIgnoreCase) ||
                    f.Name.Equals("Thumbs.db", StringComparison.OrdinalIgnoreCase)).ToList();

                if (junkFiles.Count == fileCount)
                {
                    return (true, "Contains only system/temp files (logs, desktop.ini)", RiskLevel.Low);
                }

                // 5. Check last access time across all files
                var lastAccessedFile = files.Max(f => 
                {
                    try { return f.LastAccessTime; }
                    catch { return DateTime.MinValue; }
                });

                var daysSinceAccess = (DateTime.Now - lastAccessedFile).TotalDays;
                var daysSinceModify = (DateTime.Now - lastWrite).TotalDays;
                var daysSinceCreation = (DateTime.Now - created).TotalDays;

                // 6. Check for uninstaller artifacts only
                var exeFiles = files.Where(f => f.Extension.Equals(".exe", StringComparison.OrdinalIgnoreCase)).ToList();
                var uninstallerOnly = exeFiles.All(f => 
                    f.Name.Contains("unins", StringComparison.OrdinalIgnoreCase) ||
                    f.Name.Contains("uninstall", StringComparison.OrdinalIgnoreCase));

                if (exeFiles.Any() && uninstallerOnly)
                {
                    return (true, "Only contains uninstaller executable(s), main app missing", RiskLevel.Low);
                }

                // 7. Very old folder that was never accessed after creation
                if (daysSinceCreation > 180 && Math.Abs(daysSinceAccess - daysSinceCreation) < 7)
                {
                    return (true, $"Created {(int)(daysSinceCreation/30)} months ago, never used since", RiskLevel.Low);
                }

                // 8. Files not accessed in a very long time (over 1 year)
                if (daysSinceAccess > 365)
                {
                    return (true, $"No files accessed in {(int)(daysSinceAccess/30)} months", RiskLevel.Low);
                }

                // 9. Files not accessed in 6+ months
                if (daysSinceAccess > 180)
                {
                    return (true, $"No files accessed in {(int)(daysSinceAccess/30)} months", RiskLevel.Medium);
                }

                // 10. Old folder, no matching program, not modified
                if (daysSinceModify > 365)
                {
                    return (true, $"Not modified in {(int)(daysSinceModify/30)} months, no matching program", RiskLevel.Medium);
                }

                // 11. Created before oldest known install and no exe files (stale data folder)
                if (created < oldestInstall && !files.Any(f => 
                    ActiveFileExtensions.Contains(f.Extension.ToLowerInvariant())))
                {
                    return (true, $"Data folder from removed program (created {created:MMM yyyy})", RiskLevel.Medium);
                }

                // 12. Check for version-specific folders (e.g., "AppName 1.0" when newer exists)
                var versionMatch = System.Text.RegularExpressions.Regex.Match(
                    folderName, @"[\s_\-]v?\d+[\.\d]+$", System.Text.RegularExpressions.RegexOptions.IgnoreCase);
                
                if (versionMatch.Success && daysSinceAccess > 90)
                {
                    var baseName = folderName.Substring(0, versionMatch.Index);
                    if (installedPrograms.Any(p => p.StartsWith(baseName, StringComparison.OrdinalIgnoreCase)))
                    {
                        return (true, $"Old version folder, newer version may be installed", RiskLevel.Medium);
                    }
                }

                // 13. Small folder with only config/data files, not accessed recently
                if (fileCount <= 10 && daysSinceAccess > 90)
                {
                    var hasNoExecutables = !files.Any(f => 
                        f.Extension.Equals(".exe", StringComparison.OrdinalIgnoreCase) ||
                        f.Extension.Equals(".dll", StringComparison.OrdinalIgnoreCase));
                    
                    if (hasNoExecutables)
                    {
                        return (true, $"Small config/data folder, unused for {(int)(daysSinceAccess/30)} months", RiskLevel.High);
                    }
                }

            }
            catch { }

            return (false, string.Empty, RiskLevel.Low);
        }

        private static bool IsProtectedFolder(string folderName)
        {
            return ProtectedFolders.Contains(folderName) ||
                   folderName.StartsWith("Microsoft", StringComparison.OrdinalIgnoreCase) ||
                   folderName.StartsWith("Windows", StringComparison.OrdinalIgnoreCase) ||
                   folderName.StartsWith(".", StringComparison.Ordinal); // Hidden folders like .git
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
            catch { return 0; }
        }

        private static (DateTime lastModified, DateTime lastAccessed, DateTime created) GetFolderDates(string folderPath)
        {
            try
            {
                var info = new DirectoryInfo(folderPath);
                return (info.LastWriteTime, info.LastAccessTime, info.CreationTime);
            }
            catch
            {
                return (DateTime.MinValue, DateTime.MinValue, DateTime.MinValue);
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

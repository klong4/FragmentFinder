using System;

namespace FragmentFinder.Models
{
    public class OrphanFolder
    {
        public string Path { get; set; } = string.Empty;
        public string Name { get; set; } = string.Empty;
        public string Category { get; set; } = string.Empty;
        public long SizeBytes { get; set; }
        public DateTime LastModified { get; set; }
        public string Reason { get; set; } = string.Empty;
        public bool IsSelected { get; set; }
        public RiskLevel Risk { get; set; }

        public string SizeFormatted => FormatBytes(SizeBytes);

        private static string FormatBytes(long bytes)
        {
            string[] sizes = { "B", "KB", "MB", "GB", "TB" };
            double len = bytes;
            int order = 0;
            while (len >= 1024 && order < sizes.Length - 1)
            {
                order++;
                len /= 1024;
            }
            return $"{len:0.##} {sizes[order]}";
        }
    }

    public enum RiskLevel
    {
        Low,      // Safe to delete
        Medium,   // Likely safe, but verify
        High      // Caution - might be needed
    }

    public enum ScanLocation
    {
        ProgramFiles,
        ProgramFilesX86,
        AppData,
        LocalAppData,
        ProgramData,
        CommonFiles,
        All
    }
}

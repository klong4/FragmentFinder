using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using FragmentFinder.Models;

namespace FragmentFinder.Services
{
    public class CleanupService
    {
        public event Action<string>? StatusUpdate;
        public event Action<int>? ProgressUpdate;

        public async Task<CleanupResult> DeleteFoldersAsync(
            IEnumerable<OrphanFolder> folders,
            bool moveToRecycleBin = true)
        {
            var result = new CleanupResult();
            var folderList = folders.ToList();
            int processed = 0;

            foreach (var folder in folderList)
            {
                processed++;
                ProgressUpdate?.Invoke((int)((processed * 100.0) / folderList.Count));
                StatusUpdate?.Invoke($"Deleting: {folder.Name}");

                try
                {
                    if (moveToRecycleBin)
                    {
                        // Use shell to move to recycle bin
                        await Task.Run(() => MoveToRecycleBin(folder.Path));
                    }
                    else
                    {
                        await Task.Run(() => Directory.Delete(folder.Path, true));
                    }

                    result.DeletedFolders.Add(folder);
                    result.TotalBytesFreed += folder.SizeBytes;
                }
                catch (Exception ex)
                {
                    result.FailedFolders.Add((folder, ex.Message));
                }
            }

            return result;
        }

        private static void MoveToRecycleBin(string path)
        {
            // Use Microsoft.VisualBasic for recycle bin support
            // Alternative: Use SHFileOperation from shell32
            try
            {
                Microsoft.VisualBasic.FileIO.FileSystem.DeleteDirectory(
                    path,
                    Microsoft.VisualBasic.FileIO.UIOption.OnlyErrorDialogs,
                    Microsoft.VisualBasic.FileIO.RecycleOption.SendToRecycleBin);
            }
            catch
            {
                // Fallback to permanent delete if recycle bin fails
                Directory.Delete(path, true);
            }
        }

        public async Task<string> CreateBackupListAsync(IEnumerable<OrphanFolder> folders, string outputPath)
        {
            var lines = new List<string>
            {
                $"FragmentFinder Backup List - {DateTime.Now:yyyy-MM-dd HH:mm:ss}",
                "=" + new string('=', 60),
                ""
            };

            foreach (var folder in folders)
            {
                lines.Add($"Path: {folder.Path}");
                lines.Add($"Size: {folder.SizeFormatted}");
                lines.Add($"Category: {folder.Category}");
                lines.Add($"Reason: {folder.Reason}");
                lines.Add($"Risk: {folder.Risk}");
                lines.Add($"Last Modified: {folder.LastModified:yyyy-MM-dd}");
                lines.Add("");
            }

            await File.WriteAllLinesAsync(outputPath, lines);
            return outputPath;
        }
    }

    public class CleanupResult
    {
        public List<OrphanFolder> DeletedFolders { get; } = new();
        public List<(OrphanFolder Folder, string Error)> FailedFolders { get; } = new();
        public long TotalBytesFreed { get; set; }

        public string BytesFreedFormatted
        {
            get
            {
                string[] sizes = { "B", "KB", "MB", "GB", "TB" };
                double len = TotalBytesFreed;
                int order = 0;
                while (len >= 1024 && order < sizes.Length - 1)
                {
                    order++;
                    len /= 1024;
                }
                return $"{len:0.##} {sizes[order]}";
            }
        }
    }
}

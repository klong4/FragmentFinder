using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using FragmentFinder.Models;

namespace FragmentFinder.Services
{
    public class CleanupService
    {
        public event Action<string>? StatusUpdate;
        public event Action<int>? ProgressUpdate;

        private const int MaxRetryAttempts = 3;
        private const int RetryDelayMs = 500;

        public async Task<CleanupResult> DeleteFoldersAsync(
            IEnumerable<OrphanFolder> folders,
            bool moveToRecycleBin = true,
            CancellationToken cancellationToken = default)
        {
            var result = new CleanupResult();
            var folderList = folders.ToList();
            int processed = 0;

            foreach (var folder in folderList)
            {
                if (cancellationToken.IsCancellationRequested)
                    break;

                processed++;
                ProgressUpdate?.Invoke((int)((processed * 100.0) / folderList.Count));
                StatusUpdate?.Invoke($"Deleting: {folder.Name}");

                try
                {
                    bool success = false;
                    Exception? lastException = null;

                    for (int attempt = 0; attempt < MaxRetryAttempts && !success; attempt++)
                    {
                        try
                        {
                            if (attempt > 0)
                            {
                                StatusUpdate?.Invoke($"Retrying: {folder.Name} (attempt {attempt + 1}/{MaxRetryAttempts})");
                                await Task.Delay(RetryDelayMs * attempt, cancellationToken);
                            }

                            if (moveToRecycleBin)
                            {
                                await Task.Run(() => MoveToRecycleBin(folder.Path), cancellationToken);
                            }
                            else
                            {
                                await Task.Run(() => DeleteFolderWithRetry(folder.Path), cancellationToken);
                            }

                            success = true;
                        }
                        catch (OperationCanceledException)
                        {
                            throw;
                        }
                        catch (Exception ex)
                        {
                            lastException = ex;
                            if (attempt == MaxRetryAttempts - 1)
                            {
                                throw;
                            }
                        }
                    }

                    if (success)
                    {
                        result.DeletedFolders.Add(folder);
                        result.TotalBytesFreed += folder.SizeBytes;
                    }
                }
                catch (OperationCanceledException)
                {
                    StatusUpdate?.Invoke("Deletion cancelled");
                    break;
                }
                catch (Exception ex)
                {
                    result.FailedFolders.Add((folder, ex.Message));
                }
            }

            return result;
        }

        private static void DeleteFolderWithRetry(string path)
        {
            if (!Directory.Exists(path))
                return;

            try
            {
                // First, remove read-only attributes from all files
                RemoveReadOnlyAttributes(path);
                
                // Delete the directory
                Directory.Delete(path, true);
            }
            catch (UnauthorizedAccessException)
            {
                // Try to take ownership and retry
                try
                {
                    RemoveReadOnlyAttributes(path);
                    Directory.Delete(path, true);
                }
                catch
                {
                    throw;
                }
            }
        }

        private static void RemoveReadOnlyAttributes(string path)
        {
            try
            {
                var dirInfo = new DirectoryInfo(path);
                
                // Remove read-only from directory itself
                if ((dirInfo.Attributes & FileAttributes.ReadOnly) == FileAttributes.ReadOnly)
                {
                    dirInfo.Attributes &= ~FileAttributes.ReadOnly;
                }

                // Remove read-only from all files
                foreach (var file in dirInfo.EnumerateFiles("*", SearchOption.AllDirectories))
                {
                    try
                    {
                        if ((file.Attributes & FileAttributes.ReadOnly) == FileAttributes.ReadOnly)
                        {
                            file.Attributes &= ~FileAttributes.ReadOnly;
                        }
                    }
                    catch { }
                }

                // Remove read-only from all subdirectories
                foreach (var dir in dirInfo.EnumerateDirectories("*", SearchOption.AllDirectories))
                {
                    try
                    {
                        if ((dir.Attributes & FileAttributes.ReadOnly) == FileAttributes.ReadOnly)
                        {
                            dir.Attributes &= ~FileAttributes.ReadOnly;
                        }
                    }
                    catch { }
                }
            }
            catch { }
        }

        private static void MoveToRecycleBin(string path)
        {
            if (!Directory.Exists(path))
                return;

            try
            {
                Microsoft.VisualBasic.FileIO.FileSystem.DeleteDirectory(
                    path,
                    Microsoft.VisualBasic.FileIO.UIOption.OnlyErrorDialogs,
                    Microsoft.VisualBasic.FileIO.RecycleOption.SendToRecycleBin);
            }
            catch (OperationCanceledException)
            {
                throw;
            }
            catch
            {
                // Fallback to permanent delete if recycle bin fails
                DeleteFolderWithRetry(path);
            }
        }

        public async Task<string> CreateBackupListAsync(
            IEnumerable<OrphanFolder> folders, 
            string outputPath,
            CancellationToken cancellationToken = default)
        {
            var lines = new List<string>
            {
                $"FragmentFinder Backup List - {DateTime.Now:yyyy-MM-dd HH:mm:ss}",
                "=" + new string('=', 60),
                ""
            };

            foreach (var folder in folders)
            {
                cancellationToken.ThrowIfCancellationRequested();
                
                lines.Add($"Path: {folder.Path}");
                lines.Add($"Size: {folder.SizeFormatted}");
                lines.Add($"Category: {folder.Category}");
                lines.Add($"Reason: {folder.Reason}");
                lines.Add($"Risk: {folder.Risk}");
                lines.Add($"Last Modified: {folder.LastModified:yyyy-MM-dd}");
                lines.Add("");
            }

            // Use FileStream with proper disposal to avoid file locking issues
            await using var fileStream = new FileStream(
                outputPath, 
                FileMode.Create, 
                FileAccess.Write, 
                FileShare.None,
                bufferSize: 4096,
                useAsync: true);
            await using var writer = new StreamWriter(fileStream);
            
            foreach (var line in lines)
            {
                await writer.WriteLineAsync(line);
            }
            
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

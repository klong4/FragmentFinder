using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using FragmentFinder.Models;
using FragmentFinder.Services;
using Microsoft.Win32;

namespace FragmentFinder
{
    public partial class MainWindow : Window
    {
        private readonly OrphanScannerService _scannerService;
        private readonly CleanupService _cleanupService;
        private CancellationTokenSource? _cancellationTokenSource;
        private List<OrphanFolder> _allOrphans = new();
        private ObservableCollection<OrphanFolder> _displayedOrphans = new();
        private bool _isInitialized = false;

        public MainWindow()
        {
            InitializeComponent();
            _scannerService = new OrphanScannerService();
            _cleanupService = new CleanupService();

            _scannerService.StatusUpdate += status => Dispatcher.Invoke(() => StatusText.Text = status);
            _scannerService.ProgressUpdate += progress => Dispatcher.Invoke(() => 
            {
                ScanProgressBar.Value = progress;
                ProgressPercent.Text = $"{progress}%";
            });

            _cleanupService.StatusUpdate += status => Dispatcher.Invoke(() => StatusText.Text = status);
            _cleanupService.ProgressUpdate += progress => Dispatcher.Invoke(() =>
            {
                ScanProgressBar.Value = progress;
                ProgressPercent.Text = $"{progress}%";
            });

            ResultsListBox.ItemsSource = _displayedOrphans;
            
            // Populate drive dropdown
            PopulateDrives();
            
            _isInitialized = true;
        }

        private void PopulateDrives()
        {
            DriveComboBox.Items.Clear();
            
            foreach (var drive in DriveInfo.GetDrives())
            {
                if (drive.IsReady && (drive.DriveType == DriveType.Fixed || drive.DriveType == DriveType.Removable))
                {
                    var label = string.IsNullOrEmpty(drive.VolumeLabel) 
                        ? $"{drive.Name.TrimEnd('\\')}" 
                        : $"{drive.Name.TrimEnd('\\')} ({drive.VolumeLabel})";
                    
                    DriveComboBox.Items.Add(new ComboBoxItem 
                    { 
                        Content = label, 
                        Tag = drive.Name 
                    });
                }
            }
            
            // Select the system drive by default
            var systemDrive = Path.GetPathRoot(Environment.SystemDirectory);
            for (int i = 0; i < DriveComboBox.Items.Count; i++)
            {
                if (DriveComboBox.Items[i] is ComboBoxItem item && 
                    item.Tag?.ToString()?.Equals(systemDrive, StringComparison.OrdinalIgnoreCase) == true)
                {
                    DriveComboBox.SelectedIndex = i;
                    break;
                }
            }
            
            if (DriveComboBox.SelectedIndex < 0 && DriveComboBox.Items.Count > 0)
                DriveComboBox.SelectedIndex = 0;
        }

        private void DriveComboBox_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            // Just allow selection, scanning will use the selected drive
        }

        private async void ScanButton_Click(object sender, RoutedEventArgs e)
        {
            if (ScanButton.Content.ToString()!.Contains("Cancel"))
            {
                _cancellationTokenSource?.Cancel();
                return;
            }

            _cancellationTokenSource = new CancellationTokenSource();
            var location = (ScanLocation)LocationComboBox.SelectedIndex;
            
            // Get selected drive
            string? selectedDrive = null;
            if (DriveComboBox.SelectedItem is ComboBoxItem selectedItem)
            {
                selectedDrive = selectedItem.Tag?.ToString();
            }

            try
            {
                SetScanningState(true);

                _allOrphans = await _scannerService.ScanAsync(location, selectedDrive, _cancellationTokenSource.Token);
                
                ApplyFilter();
                UpdateSummary();
            }
            catch (OperationCanceledException)
            {
                StatusText.Text = "Scan cancelled";
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error during scan: {ex.Message}", "Scan Error", 
                    MessageBoxButton.OK, MessageBoxImage.Error);
            }
            finally
            {
                SetScanningState(false);
            }
        }

        private void SetScanningState(bool isScanning)
        {
            ScanButton.Content = isScanning ? "❌ Cancel" : "🔎 Start Scan";
            ProgressPanel.Visibility = isScanning ? Visibility.Visible : Visibility.Collapsed;
            LocationComboBox.IsEnabled = !isScanning;
            DeleteButton.IsEnabled = !isScanning && _displayedOrphans.Any(o => o.IsSelected);
            ExportButton.IsEnabled = !isScanning && _allOrphans.Any();
            OpenFolderButton.IsEnabled = !isScanning && _displayedOrphans.Any(o => o.IsSelected);

            if (isScanning)
            {
                ScanProgressBar.Value = 0;
                ProgressPercent.Text = "0%";
            }
        }

        private void ApplyFilter()
        {
            var filterIndex = FilterComboBox.SelectedIndex;
            IEnumerable<OrphanFolder> filtered = _allOrphans;

            filtered = filterIndex switch
            {
                1 => _allOrphans.Where(o => o.Risk == RiskLevel.Low),
                2 => _allOrphans.Where(o => o.Risk == RiskLevel.Medium),
                3 => _allOrphans.Where(o => o.Risk == RiskLevel.High),
                _ => _allOrphans
            };

            _displayedOrphans.Clear();
            foreach (var orphan in filtered)
            {
                _displayedOrphans.Add(orphan);
            }

            EmptyStatePanel.Visibility = _displayedOrphans.Any() ? Visibility.Collapsed : Visibility.Visible;
            UpdateSelectedSize();
        }

        private void UpdateSummary()
        {
            var totalSize = _allOrphans.Sum(o => o.SizeBytes);
            var sizeStr = FormatBytes(totalSize);
            ResultsSummary.Text = $"Found {_allOrphans.Count} orphan folder(s) • Total: {sizeStr}";
        }

        private void UpdateSelectedSize()
        {
            var selectedSize = _displayedOrphans.Where(o => o.IsSelected).Sum(o => o.SizeBytes);
            var selectedCount = _displayedOrphans.Count(o => o.IsSelected);

            if (selectedCount > 0)
            {
                SelectedSizeText.Text = $"Selected: {selectedCount} items ({FormatBytes(selectedSize)})";
            }
            else
            {
                SelectedSizeText.Text = "";
            }

            DeleteButton.IsEnabled = selectedCount > 0;
            OpenFolderButton.IsEnabled = selectedCount > 0;
        }

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

        private void SelectAllCheckBox_Click(object sender, RoutedEventArgs e)
        {
            var isChecked = SelectAllCheckBox.IsChecked == true;
            foreach (var orphan in _displayedOrphans)
            {
                orphan.IsSelected = isChecked;
            }
            ResultsListBox.Items.Refresh();
            UpdateSelectedSize();
        }

        private void ItemCheckBox_Changed(object sender, RoutedEventArgs e)
        {
            UpdateSelectedSize();
        }

        private void FilterComboBox_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if (_isInitialized)
            {
                ApplyFilter();
            }
        }

        private async void DeleteButton_Click(object sender, RoutedEventArgs e)
        {
            var selectedItems = _displayedOrphans.Where(o => o.IsSelected).ToList();
            if (!selectedItems.Any())
            {
                MessageBox.Show("No items selected for deletion.", "No Selection",
                    MessageBoxButton.OK, MessageBoxImage.Information);
                return;
            }

            var highRiskCount = selectedItems.Count(o => o.Risk == RiskLevel.High);
            var mediumRiskCount = selectedItems.Count(o => o.Risk == RiskLevel.Medium);

            var warningMessage = $"You are about to delete {selectedItems.Count} folder(s).\n\n";
            
            if (highRiskCount > 0 || mediumRiskCount > 0)
            {
                warningMessage += $"⚠️ Warning:\n";
                if (highRiskCount > 0)
                    warningMessage += $"  • {highRiskCount} HIGH risk item(s)\n";
                if (mediumRiskCount > 0)
                    warningMessage += $"  • {mediumRiskCount} MEDIUM risk item(s)\n";
                warningMessage += "\n";
            }

            var useRecycleBin = SafeModeCheckBox.IsChecked == true;
            warningMessage += useRecycleBin 
                ? "Items will be moved to the Recycle Bin." 
                : "⚠️ Items will be PERMANENTLY deleted!";

            var result = MessageBox.Show(warningMessage, "Confirm Deletion",
                MessageBoxButton.YesNo, MessageBoxImage.Warning);

            if (result != MessageBoxResult.Yes) return;

            try
            {
                SetScanningState(true);
                StatusText.Text = "Deleting folders...";

                var cleanupResult = await _cleanupService.DeleteFoldersAsync(selectedItems, useRecycleBin);

                // Remove deleted items from lists
                foreach (var deleted in cleanupResult.DeletedFolders)
                {
                    _allOrphans.Remove(deleted);
                    _displayedOrphans.Remove(deleted);
                }

                // Show results
                var message = $"Successfully deleted {cleanupResult.DeletedFolders.Count} folder(s).\n" +
                              $"Space freed: {cleanupResult.BytesFreedFormatted}";

                if (cleanupResult.FailedFolders.Any())
                {
                    message += $"\n\n⚠️ Failed to delete {cleanupResult.FailedFolders.Count} folder(s):\n";
                    foreach (var (folder, error) in cleanupResult.FailedFolders.Take(5))
                    {
                        message += $"  • {folder.Name}: {error}\n";
                    }
                    if (cleanupResult.FailedFolders.Count > 5)
                    {
                        message += $"  ... and {cleanupResult.FailedFolders.Count - 5} more";
                    }
                }

                MessageBox.Show(message, "Cleanup Complete",
                    MessageBoxButton.OK, MessageBoxImage.Information);

                UpdateSummary();
                UpdateSelectedSize();
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error during cleanup: {ex.Message}", "Cleanup Error",
                    MessageBoxButton.OK, MessageBoxImage.Error);
            }
            finally
            {
                SetScanningState(false);
            }
        }

        private async void ExportButton_Click(object sender, RoutedEventArgs e)
        {
            var dialog = new SaveFileDialog
            {
                Filter = "Text files (*.txt)|*.txt|All files (*.*)|*.*",
                DefaultExt = ".txt",
                FileName = $"FragmentFinder_Export_{DateTime.Now:yyyyMMdd_HHmmss}"
            };

            if (dialog.ShowDialog() == true)
            {
                try
                {
                    await _cleanupService.CreateBackupListAsync(_allOrphans, dialog.FileName);
                    MessageBox.Show($"Export saved to:\n{dialog.FileName}", "Export Complete",
                        MessageBoxButton.OK, MessageBoxImage.Information);
                }
                catch (Exception ex)
                {
                    MessageBox.Show($"Error exporting: {ex.Message}", "Export Error",
                        MessageBoxButton.OK, MessageBoxImage.Error);
                }
            }
        }

        private void OpenFolderButton_Click(object sender, RoutedEventArgs e)
        {
            var selectedItem = _displayedOrphans.FirstOrDefault(o => o.IsSelected);
            if (selectedItem != null && Directory.Exists(selectedItem.Path))
            {
                Process.Start("explorer.exe", $"/select,\"{selectedItem.Path}\"");
            }
        }
    }
}

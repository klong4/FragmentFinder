# FragmentFinder

A dark-themed Windows application for finding and safely removing orphaned program folders.

## Features

- **Smart Detection**: Scans for orphan folders by comparing against Windows Registry installed programs
- **Risk Assessment**: Categorizes findings as Low, Medium, or High risk
- **Safe Deletion**: Option to move to Recycle Bin instead of permanent deletion
- **Multiple Scan Locations**: 
  - Program Files
  - Program Files (x86)
  - AppData (Roaming & Local)
  - ProgramData
  - Common Files

## Building

### Requirements
- .NET 8.0 SDK
- Windows 10/11

### Build Commands
```bash
# Restore dependencies
dotnet restore

# Build in Debug mode
dotnet build

# Build in Release mode
dotnet build -c Release

# Run the application
dotnet run
```

## Usage

1. **Select Scan Location**: Choose which folder(s) to scan from the dropdown
2. **Start Scan**: Click "Start Scan" to begin analysis
3. **Review Results**: Check the detected orphan folders and their risk levels
4. **Filter Results**: Use the filter dropdown to show only specific risk levels
5. **Select Items**: Check items you want to remove (Low risk items are auto-selected)
6. **Safe Mode**: Keep "Safe Mode" checked to move items to Recycle Bin
7. **Delete**: Click "Delete Selected" to clean up

## Risk Levels

- **Low** (Green): Safe to delete - empty folders, uninstaller artifacts, old temp files
- **Medium** (Orange): Likely safe - folders not modified in 12+ months
- **High** (Red): Use caution - folders not modified in 6-12 months

## Protected Folders

The application automatically protects system-critical folders including:
- Microsoft/Windows folders
- Driver folders (NVIDIA, AMD, Intel, Realtek)
- .NET and SDK folders
- System components

## Safety Features

- Checks against Windows Registry for installed programs
- Compares install paths from registry entries
- Never deletes protected system folders
- Recycle Bin support for easy recovery
- Export list before deletion for backup

## Dark Theme

The application features a modern dark theme with neon cyan, magenta, and green accents for excellent visibility and reduced eye strain.

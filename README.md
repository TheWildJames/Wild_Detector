# Wild Detector

A comprehensive, single-file script to detect SUSFS (susfs4ksu) root hiding mechanisms without requiring root privileges.

## Quick Usage

### Method 1: Direct download and execute with curl
```bash
curl -s https://raw.githubusercontent.com/TheWildJames/Wild_Detector/main/wild_detector.sh | bash
```

### Method 2: Direct download and execute with wget
```bash
wget -qO- https://raw.githubusercontent.com/TheWildJames/Wild_Detector/main/wild_detector.sh | bash
```

### Method 3: Download first, then execute
```bash
# Download the script
curl -O https://raw.githubusercontent.com/TheWildJames/Wild_Detector/main/wild_detector.sh

# Make it executable
chmod +x wild_detector.sh

# Run it
./wild_detector.sh
```

## What it Detects

This script detects various SUSFS hiding mechanisms including:

- **Hardcoded Fake Directory Name**: Searches for the `..5.u.S` fake directory name used by SUSFS
- **TWRP Directory Hiding**: Detects hidden `/sdcard/TWRP` directories
- **Directory Listing Inconsistencies**: Compares different directory listing methods
- **Kernel Symbol Detection**: Searches for SUSFS symbols in `/proc/kallsyms`
- **Process Analysis**: Identifies SUSFS and KernelSU related processes
- **Mount Point Analysis**: Checks for suspicious filesystem mounts
- **Dcache Manipulation**: Detects unusual filesystem caching behavior
- **Timing Analysis**: Identifies unusual access timing patterns
- **KernelSU Module Detection**: Searches for KernelSU and SUSFS module files

## Output

The script provides:
- Detailed detection results with confidence scoring
- Color-coded output for easy reading
- Comprehensive final report with recommendations
- Technical details about detection methods

## Detection Score

- **200+**: High confidence SUSFS is active
- **100-199**: Medium confidence SUSFS may be active  
- **50-99**: Low confidence, some indicators detected
- **<50**: Minimal indicators, unlikely to be SUSFS

## Technical Details

### The `..5.u.S` Signature

SUSFS uses a hardcoded fake directory name `..5.u.S` for dcache manipulation. When hiding directories, SUSFS redirects filesystem lookups to this fake name, making hidden directories appear non-existent to non-root processes.

### Detection Methods

The script exploits several weaknesses in SUSFS v1.5.9:
1. **Hardcoded patterns** that can be searched for
2. **Syscall inconsistencies** between different access methods
3. **Timing anomalies** in filesystem operations
4. **Mount discrepancies** and overlay filesystem usage
5. **Process and kernel module signatures**

## Requirements

- Android device with shell access (adb shell)
- No root privileges required
- Standard Unix utilities (ls, find, stat, grep, etc.)

## Limitations

- Detection effectiveness may vary on different Android versions
- Future SUSFS versions might use dynamic fake names
- Some detection methods may produce false positives
- Requires shell access to the device

## Contributing

To improve detection capabilities:
1. Test on different Android versions and devices
2. Add new detection patterns for SUSFS updates
3. Optimize timing-based detection methods
4. Report false positives and negatives

## License

This script is provided for educational and security research purposes.
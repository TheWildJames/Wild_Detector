#!/bin/bash

# Wild Detector - Comprehensive Root Hiding Detection
# Detects SUSFS (susfs4ksu) hiding mechanisms without root privileges
# Usage: curl -s https://raw.githubusercontent.com/TheWildJames/Wild_Detector/main/wild_detector.sh | bash
# Or: wget -qO- https://raw.githubusercontent.com/TheWildJames/Wild_Detector/main/wild_detector.sh | bash

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Global variables
DETECTION_SCORE=0
DETECTED_INDICATORS=()
SUSFS_FAKE_NAME="..5.u.S"
TEST_DIRS=("/data/data" "/sdcard" "/storage/emulated/0" "/data/local/tmp" "/system")
TWRP_PATHS=("/sdcard/TWRP" "/storage/emulated/0/TWRP" "/external_sd/TWRP")

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

add_detection() {
    local indicator="$1"
    local score="$2"
    local explanation="$3"
    DETECTED_INDICATORS+=("$indicator")
    DETECTION_SCORE=$((DETECTION_SCORE + score))
    log_warning "DETECTED: $indicator (+$score points)"
    if [ -n "$explanation" ]; then
        echo -e "${BLUE}    → Explanation: $explanation${NC}"
    fi
}

# System information gathering
gather_system_info() {
    log_info "Gathering system information..."
    echo "Device: $(getprop ro.product.model 2>/dev/null || echo 'Unknown')"
    echo "Android Version: $(getprop ro.build.version.release 2>/dev/null || echo 'Unknown')"
    echo "Kernel: $(uname -r)"
    echo "Architecture: $(uname -m)"
    echo "Date: $(date)"
    echo "----------------------------------------"
}

# Check for hardcoded fake directory name
check_fake_directory_name() {
    log_info "Checking for hardcoded fake directory name ($SUSFS_FAKE_NAME)..."
    echo "    This checks for SUSFS's signature fake directory used for dcache manipulation"
    
    for base_dir in "${TEST_DIRS[@]}"; do
        if [ -d "$base_dir" ]; then
            # Try to access the fake directory
            if ls "$base_dir/$SUSFS_FAKE_NAME" >/dev/null 2>&1; then
                add_detection "Fake directory '$SUSFS_FAKE_NAME' accessible in $base_dir" 50 "SUSFS redirects hidden directory access to this hardcoded fake name"
            fi
            
            # Check if fake directory appears in listings
            if ls -la "$base_dir" 2>/dev/null | grep -q "$SUSFS_FAKE_NAME"; then
                add_detection "Fake directory '$SUSFS_FAKE_NAME' visible in $base_dir listing" 40 "The fake directory should never be visible in normal listings"
            fi
            
            # Test stat operations
            if stat "$base_dir/$SUSFS_FAKE_NAME" >/dev/null 2>&1; then
                add_detection "Fake directory '$SUSFS_FAKE_NAME' responds to stat in $base_dir" 45 "stat() syscall returns data for the fake directory, indicating dcache manipulation"
            fi
        fi
    done
}

# Check for directory listing inconsistencies
check_directory_inconsistencies() {
    log_info "Checking for directory listing inconsistencies..."
    echo "    Different syscalls may show different results when directories are hidden"
    
    for test_dir in "${TEST_DIRS[@]}"; do
        if [ -d "$test_dir" ]; then
            # Compare different listing methods
            ls_count=$(ls -1 "$test_dir" 2>/dev/null | wc -l)
            find_count=$(find "$test_dir" -maxdepth 1 -type d 2>/dev/null | wc -l)
            
            if [ "$ls_count" -ne "$find_count" ] && [ "$ls_count" -gt 0 ] && [ "$find_count" -gt 0 ]; then
                add_detection "Directory count mismatch in $test_dir (ls: $ls_count, find: $find_count)" 25 "Different syscalls (readdir vs getdents) show inconsistent results due to selective hiding"
            fi
        fi
    done
}

# Check for TWRP hiding
check_twrp_hiding() {
    log_info "Checking for TWRP directory hiding..."
    echo "    TWRP directories are commonly hidden by SUSFS to avoid detection"
    
    for twrp_path in "${TWRP_PATHS[@]}"; do
        local parent_dir=$(dirname "$twrp_path")
        local twrp_name=$(basename "$twrp_path")
        
        if [ -d "$parent_dir" ]; then
            # Check if TWRP directory is hidden
            if ! ls -la "$parent_dir" 2>/dev/null | grep -q "$twrp_name"; then
                # But try to access it directly
                if [ -d "$twrp_path" ] || stat "$twrp_path" >/dev/null 2>&1; then
                    add_detection "TWRP directory hidden but accessible: $twrp_path" 60 "Directory exists and is accessible but doesn't appear in parent directory listings"
                fi
                
                # Check for TWRP-related files that might be visible
                if ls "$parent_dir" 2>/dev/null | grep -qi "twrp\|recovery"; then
                    add_detection "TWRP-related files found while TWRP dir hidden in $parent_dir" 30 "Related files are visible while main TWRP directory is hidden"
                fi
            fi
            
            # Test timing differences
            start_time=$(date +%s%N)
            ls "$twrp_path" >/dev/null 2>&1
            end_time=$(date +%s%N)
            access_time=$((end_time - start_time))
            
            start_time=$(date +%s%N)
            ls "$parent_dir/nonexistent_dir_test" >/dev/null 2>&1
            end_time=$(date +%s%N)
            nonexistent_time=$((end_time - start_time))
            
            # If accessing TWRP takes significantly longer, it might be being processed by SUSFS
            if [ "$access_time" -gt $((nonexistent_time * 2)) ] && [ "$access_time" -gt 1000000 ]; then
                add_detection "Unusual timing accessing $twrp_path (${access_time}ns vs ${nonexistent_time}ns)" 20 "Kernel processing time suggests path is being intercepted and redirected"
            fi
        fi
    done
}

# Check for SUSFS kernel symbols
check_kernel_symbols() {
    log_info "Checking for SUSFS kernel symbols..."
    echo "    Kernel symbols reveal loaded SUSFS functions and data structures"
    
    if [ -r "/proc/kallsyms" ]; then
        susfs_symbols=$(grep -i "susfs" /proc/kallsyms 2>/dev/null | wc -l)
        if [ "$susfs_symbols" -gt 0 ]; then
            add_detection "SUSFS kernel symbols found in /proc/kallsyms ($susfs_symbols symbols)" 70 "Kernel module symbols indicate SUSFS is loaded and active"
        fi
        
        # Check for specific SUSFS functions
        if grep -q "susfs_add_sus_path" /proc/kallsyms 2>/dev/null; then
            add_detection "susfs_add_sus_path function found in kernel" 80 "Core SUSFS function for adding paths to hide list is present"
        fi
        
        if grep -q "susfs_fake_qstr_name" /proc/kallsyms 2>/dev/null; then
            add_detection "susfs_fake_qstr_name symbol found in kernel" 90 "The hardcoded fake directory name variable is loaded in kernel memory"
        fi
    fi
}

# Check for suspicious processes
check_suspicious_processes() {
    log_info "Checking for suspicious processes..."
    echo "    Root management and hiding processes may indicate active concealment"
    
    # Check for SUSFS-related processes
    if ps aux 2>/dev/null | grep -i "susfs" | grep -v grep; then
        add_detection "SUSFS-related processes found" 40 "Userspace processes managing SUSFS configuration or operation"
    fi
    
    # Check for KernelSU processes
    if ps aux 2>/dev/null | grep -i "kernelsu\|ksu" | grep -v grep; then
        add_detection "KernelSU-related processes found" 30 "KernelSU daemon or management processes are running"
    fi
    
    # Check for root hiding related processes
    if ps aux 2>/dev/null | grep -E "(magisk|supersu|chainfire)" | grep -v grep; then
        add_detection "Root management processes detected" 20 "Other root management solutions that may use hiding techniques"
    fi
}

# Check mount points
check_mount_points() {
    log_info "Checking mount points for anomalies..."
    echo "    Unusual mounts may indicate filesystem manipulation or overlay hiding"
    
    # Check for suspicious mounts
    if mount 2>/dev/null | grep -i "susfs\|kernelsu"; then
        add_detection "SUSFS/KernelSU related mounts found" 50 "Direct filesystem mounts related to root hiding infrastructure"
    fi
    
    # Check for overlay mounts that might hide directories
    overlay_count=$(mount 2>/dev/null | grep -c "overlay" || echo 0)
    if [ "$overlay_count" -gt 5 ]; then
        add_detection "High number of overlay mounts detected ($overlay_count)" 15 "Excessive overlay filesystems may be used to hide or redirect access"
    fi
}

# Check filesystem behavior patterns
check_filesystem_behavior() {
    log_info "Checking filesystem behavior patterns..."
    echo "    Filesystem metadata inconsistencies reveal dcache manipulation"
    
    # Test inode consistency
    for test_dir in "${TEST_DIRS[@]}"; do
        if [ -d "$test_dir" ]; then
            # Get inode of directory
            dir_inode=$(stat -c "%i" "$test_dir" 2>/dev/null || echo "0")
            
            # Try to access via fake name and compare
            fake_inode=$(stat -c "%i" "$test_dir/$SUSFS_FAKE_NAME" 2>/dev/null || echo "0")
            
            if [ "$fake_inode" != "0" ] && [ "$fake_inode" != "$dir_inode" ]; then
                add_detection "Inode inconsistency with fake directory in $test_dir" 35 "Fake directory has different inode, indicating filesystem redirection"
            fi
        fi
    done
}

# Advanced dcache manipulation detection
check_dcache_manipulation() {
    log_info "Checking for dcache manipulation..."
    echo "    Timing analysis reveals kernel-level directory cache interference"
    
    for base_dir in "${TEST_DIRS[@]}"; do
        if [ -d "$base_dir" ]; then
            # Test multiple access patterns to the same fake directory
            for i in {1..3}; do
                start_time=$(date +%s%N)
                ls "$base_dir/$SUSFS_FAKE_NAME" >/dev/null 2>&1
                end_time=$(date +%s%N)
                access_times[$i]=$((end_time - start_time))
            done
            
            # Check for unusual timing patterns (dcache hits vs misses)
            if [ "${access_times[1]}" -gt $((${access_times[2]} * 3)) ] || [ "${access_times[1]}" -gt $((${access_times[3]} * 3)) ]; then
                add_detection "Unusual dcache timing pattern in $base_dir" 25 "First access takes significantly longer, suggesting dcache manipulation or redirection"
            fi
        fi
    done
}

# Check for KernelSU module signatures
check_kernelsu_signatures() {
    log_info "Checking for KernelSU module signatures..."
    echo "    KernelSU modules and configuration files indicate root infrastructure"
    
    # Check for KernelSU files
    ksu_files=("/data/adb/ksu" "/data/adb/modules" "/system/etc/init/kernelsu.rc")
    for ksu_file in "${ksu_files[@]}"; do
        if [ -e "$ksu_file" ]; then
            add_detection "KernelSU file found: $ksu_file" 40 "Core KernelSU infrastructure files present on system"
        fi
    done
    
    # Check for SUSFS module specifically
    if [ -d "/data/adb/modules/susfs4ksu" ]; then
        add_detection "SUSFS4KSU module directory found" 85 "SUSFS module is installed and likely active through KernelSU"
    fi
    
    # Check module.prop files for SUSFS
    if find /data/adb/modules -name "module.prop" -exec grep -l "susfs" {} \; 2>/dev/null | head -1; then
        add_detection "SUSFS module.prop found" 80 "SUSFS module configuration file indicates installation"
    fi
}

# Comprehensive TWRP detection
check_twrp_comprehensive() {
    log_info "Performing comprehensive TWRP detection..."
    echo "    TWRP artifacts may be hidden but leave traces in configuration and backups"
    
    # Check for TWRP configuration files
    twrp_configs=("/sdcard/.twrps" "/sdcard/TWRP/.twrps" "/external_sd/.twrps")
    for config in "${twrp_configs[@]}"; do
        if [ -f "$config" ]; then
            add_detection "TWRP configuration file found: $config" 45 "TWRP settings file indicates custom recovery usage"
        fi
    done
    
    # Check for TWRP backup signatures
    if find /sdcard -name "*.win" -o -name "recovery.log" 2>/dev/null | head -1; then
        add_detection "TWRP backup files detected" 35 "TWRP backup artifacts suggest custom recovery has been used"
    fi
    
    # Check recovery partition
    if [ -b "/dev/block/by-name/recovery" ]; then
        # Try to read recovery partition header (first 2048 bytes)
        if dd if=/dev/block/by-name/recovery bs=2048 count=1 2>/dev/null | strings | grep -qi "twrp\|team.win"; then
            add_detection "TWRP signature found in recovery partition" 60 "TWRP is installed in recovery partition"
        fi
    fi
}

# Generate final report
generate_report() {
    echo ""
    echo "========================================"
    echo "         WILD DETECTOR REPORT"
    echo "========================================"
    echo ""
    
    if [ ${#DETECTED_INDICATORS[@]} -eq 0 ]; then
        log_success "No SUSFS indicators detected. System appears clean."
        echo "Detection Score: $DETECTION_SCORE/1000"
    else
        echo "DETECTED INDICATORS:"
        for indicator in "${DETECTED_INDICATORS[@]}"; do
            echo "  • $indicator"
        done
        echo ""
        echo "Detection Score: $DETECTION_SCORE/1000"
        echo ""
        
        if [ "$DETECTION_SCORE" -ge 200 ]; then
            log_error "HIGH CONFIDENCE: SUSFS is likely active on this system"
            echo "    Multiple strong indicators suggest active directory hiding"
        elif [ "$DETECTION_SCORE" -ge 100 ]; then
            log_warning "MEDIUM CONFIDENCE: SUSFS may be active on this system"
            echo "    Several indicators detected, further investigation recommended"
        elif [ "$DETECTION_SCORE" -ge 50 ]; then
            log_warning "LOW CONFIDENCE: Some SUSFS indicators detected"
            echo "    Minor anomalies found, could be false positives"
        else
            log_info "MINIMAL INDICATORS: Unlikely to be SUSFS, but some anomalies detected"
            echo "    Very few indicators, likely normal system behavior"
        fi
    fi
    
    echo ""
    echo "WHAT THIS MEANS:"
    if [ "$DETECTION_SCORE" -ge 100 ]; then
        echo "  • Root hiding is likely active on this device"
        echo "  • Sensitive directories (/sdcard/TWRP, root files) may be invisible"
        echo "  • Apps checking for root may be deceived"
        echo "  • Security assessments may miss critical evidence"
        echo "  • Banking/DRM apps might still function despite root access"
    else
        echo "  • No significant evidence of directory hiding"
        echo "  • Root detection should work normally"
        echo "  • Standard security posture appears intact"
    fi
    
    echo ""
    echo "HOW SUSFS WORKS:"
    echo "  • Intercepts filesystem calls at kernel level"
    echo "  • Redirects hidden directory access to fake name: '$SUSFS_FAKE_NAME'"
    echo "  • Manipulates directory cache (dcache) to hide entries"
    echo "  • Works transparently without app modifications"
    echo "  • Commonly hides: TWRP, Magisk, root binaries, modules"
    
    echo ""
    echo "DETECTION METHODS USED:"
    echo "  • Hardcoded fake directory name detection"
    echo "  • Directory listing inconsistency analysis"
    echo "  • Filesystem timing pattern analysis"
    echo "  • Kernel symbol table inspection"
    echo "  • Process and mount point analysis"
    echo "  • TWRP artifact detection"
    echo "  • KernelSU module signature detection"
    
    echo ""
    echo "NOTE: This detection works without root privileges"
    echo "      and targets SUSFS v1.5.9 specifically"
    echo ""
    echo "========================================"
}

# Main execution
main() {
    echo "Wild Detector v1.0 - Advanced Root Hiding Detection"
    echo "Detecting susfs4ksu root hiding mechanisms..."
    echo ""
    echo "SUSFS (susfs4ksu) is a kernel-level directory hiding system that:"
    echo "• Hides sensitive directories like /sdcard/TWRP from apps"
    echo "• Uses dcache manipulation to redirect filesystem calls"
    echo "• Employs a hardcoded fake directory name: '$SUSFS_FAKE_NAME'"
    echo "• Operates transparently at the kernel level"
    echo ""
    echo "This detector analyzes filesystem behavior patterns to identify"
    echo "active SUSFS installations without requiring root privileges."
    echo ""
    echo "Starting detection..."
    echo ""
    
    gather_system_info
    
    # Run all detection methods
    check_fake_directory_name
    check_directory_inconsistencies
    check_twrp_hiding
    check_kernel_symbols
    check_suspicious_processes
    check_mount_points
    check_filesystem_behavior
    check_dcache_manipulation
    check_kernelsu_signatures
    check_twrp_comprehensive
    
    # Generate final report
    generate_report
}

# Execute main function
main "$@"
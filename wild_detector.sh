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
    DETECTED_INDICATORS+=("$indicator")
    DETECTION_SCORE=$((DETECTION_SCORE + score))
    log_warning "DETECTED: $indicator (+$score points)"
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
    
    for base_dir in "${TEST_DIRS[@]}"; do
        if [ -d "$base_dir" ]; then
            # Try to access the fake directory
            if ls "$base_dir/$SUSFS_FAKE_NAME" >/dev/null 2>&1; then
                add_detection "Fake directory '$SUSFS_FAKE_NAME' accessible in $base_dir" 50
            fi
            
            # Check if fake directory appears in listings
            if ls -la "$base_dir" 2>/dev/null | grep -q "$SUSFS_FAKE_NAME"; then
                add_detection "Fake directory '$SUSFS_FAKE_NAME' visible in $base_dir listing" 40
            fi
            
            # Test stat operations
            if stat "$base_dir/$SUSFS_FAKE_NAME" >/dev/null 2>&1; then
                add_detection "Fake directory '$SUSFS_FAKE_NAME' responds to stat in $base_dir" 45
            fi
        fi
    done
}

# Check for directory listing inconsistencies
check_directory_inconsistencies() {
    log_info "Checking for directory listing inconsistencies..."
    
    for test_dir in "${TEST_DIRS[@]}"; do
        if [ -d "$test_dir" ]; then
            # Compare different listing methods
            ls_count=$(ls -1 "$test_dir" 2>/dev/null | wc -l)
            find_count=$(find "$test_dir" -maxdepth 1 -type d 2>/dev/null | wc -l)
            
            if [ "$ls_count" -ne "$find_count" ] && [ "$ls_count" -gt 0 ] && [ "$find_count" -gt 0 ]; then
                add_detection "Directory count mismatch in $test_dir (ls: $ls_count, find: $find_count)" 25
            fi
        fi
    done
}

# Check for TWRP hiding
check_twrp_hiding() {
    log_info "Checking for TWRP directory hiding..."
    
    for twrp_path in "${TWRP_PATHS[@]}"; do
        local parent_dir=$(dirname "$twrp_path")
        local twrp_name=$(basename "$twrp_path")
        
        if [ -d "$parent_dir" ]; then
            # Check if TWRP directory is hidden
            if ! ls -la "$parent_dir" 2>/dev/null | grep -q "$twrp_name"; then
                # But try to access it directly
                if [ -d "$twrp_path" ] || stat "$twrp_path" >/dev/null 2>&1; then
                    add_detection "TWRP directory hidden but accessible: $twrp_path" 60
                fi
                
                # Check for TWRP-related files that might be visible
                if ls "$parent_dir" 2>/dev/null | grep -qi "twrp\|recovery"; then
                    add_detection "TWRP-related files found while TWRP dir hidden in $parent_dir" 30
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
                add_detection "Unusual timing accessing $twrp_path (${access_time}ns vs ${nonexistent_time}ns)" 20
            fi
        fi
    done
}

# Check for SUSFS kernel symbols
check_kernel_symbols() {
    log_info "Checking for SUSFS kernel symbols..."
    
    if [ -r "/proc/kallsyms" ]; then
        susfs_symbols=$(grep -i "susfs" /proc/kallsyms 2>/dev/null | wc -l)
        if [ "$susfs_symbols" -gt 0 ]; then
            add_detection "SUSFS kernel symbols found in /proc/kallsyms ($susfs_symbols symbols)" 70
        fi
        
        # Check for specific SUSFS functions
        if grep -q "susfs_add_sus_path" /proc/kallsyms 2>/dev/null; then
            add_detection "susfs_add_sus_path function found in kernel" 80
        fi
        
        if grep -q "susfs_fake_qstr_name" /proc/kallsyms 2>/dev/null; then
            add_detection "susfs_fake_qstr_name symbol found in kernel" 90
        fi
    fi
}

# Check for suspicious processes
check_suspicious_processes() {
    log_info "Checking for suspicious processes..."
    
    # Check for SUSFS-related processes
    if ps aux 2>/dev/null | grep -i "susfs" | grep -v grep; then
        add_detection "SUSFS-related processes found" 40
    fi
    
    # Check for KernelSU processes
    if ps aux 2>/dev/null | grep -i "kernelsu\|ksu" | grep -v grep; then
        add_detection "KernelSU-related processes found" 30
    fi
    
    # Check for root hiding related processes
    if ps aux 2>/dev/null | grep -E "(magisk|supersu|chainfire)" | grep -v grep; then
        add_detection "Root management processes detected" 20
    fi
}

# Check mount points
check_mount_points() {
    log_info "Checking mount points for anomalies..."
    
    # Check for suspicious mounts
    if mount 2>/dev/null | grep -i "susfs\|kernelsu"; then
        add_detection "SUSFS/KernelSU related mounts found" 50
    fi
    
    # Check for overlay mounts that might hide directories
    overlay_count=$(mount 2>/dev/null | grep -c "overlay" || echo 0)
    if [ "$overlay_count" -gt 5 ]; then
        add_detection "High number of overlay mounts detected ($overlay_count)" 15
    fi
}

# Check filesystem behavior patterns
check_filesystem_behavior() {
    log_info "Checking filesystem behavior patterns..."
    
    # Test inode consistency
    for test_dir in "${TEST_DIRS[@]}"; do
        if [ -d "$test_dir" ]; then
            # Get inode of directory
            dir_inode=$(stat -c "%i" "$test_dir" 2>/dev/null || echo "0")
            
            # Try to access via fake name and compare
            fake_inode=$(stat -c "%i" "$test_dir/$SUSFS_FAKE_NAME" 2>/dev/null || echo "0")
            
            if [ "$fake_inode" != "0" ] && [ "$fake_inode" != "$dir_inode" ]; then
                add_detection "Inode inconsistency with fake directory in $test_dir" 35
            fi
        fi
    done
}

# Advanced dcache manipulation detection
check_dcache_manipulation() {
    log_info "Checking for dcache manipulation..."
    
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
                add_detection "Unusual dcache timing pattern in $base_dir" 25
            fi
        fi
    done
}

# Check for KernelSU module signatures
check_kernelsu_signatures() {
    log_info "Checking for KernelSU module signatures..."
    
    # Check for KernelSU files
    ksu_files=("/data/adb/ksu" "/data/adb/modules" "/system/etc/init/kernelsu.rc")
    for ksu_file in "${ksu_files[@]}"; do
        if [ -e "$ksu_file" ]; then
            add_detection "KernelSU file found: $ksu_file" 40
        fi
    done
    
    # Check for SUSFS module specifically
    if [ -d "/data/adb/modules/susfs4ksu" ]; then
        add_detection "SUSFS4KSU module directory found" 85
    fi
    
    # Check module.prop files for SUSFS
    if find /data/adb/modules -name "module.prop" -exec grep -l "susfs" {} \; 2>/dev/null | head -1; then
        add_detection "SUSFS module.prop found" 80
    fi
}

# Comprehensive TWRP detection
check_twrp_comprehensive() {
    log_info "Performing comprehensive TWRP detection..."
    
    # Check for TWRP configuration files
    twrp_configs=("/sdcard/.twrps" "/sdcard/TWRP/.twrps" "/external_sd/.twrps")
    for config in "${twrp_configs[@]}"; do
        if [ -f "$config" ]; then
            add_detection "TWRP configuration file found: $config" 45
        fi
    done
    
    # Check for TWRP backup signatures
    if find /sdcard -name "*.win" -o -name "recovery.log" 2>/dev/null | head -1; then
        add_detection "TWRP backup files detected" 35
    fi
    
    # Check recovery partition
    if [ -b "/dev/block/by-name/recovery" ]; then
        # Try to read recovery partition header (first 2048 bytes)
        if dd if=/dev/block/by-name/recovery bs=2048 count=1 2>/dev/null | strings | grep -qi "twrp\|team.win"; then
            add_detection "TWRP signature found in recovery partition" 60
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
        elif [ "$DETECTION_SCORE" -ge 100 ]; then
            log_warning "MEDIUM CONFIDENCE: SUSFS may be active on this system"
        elif [ "$DETECTION_SCORE" -ge 50 ]; then
            log_warning "LOW CONFIDENCE: Some SUSFS indicators detected"
        else
            log_info "MINIMAL INDICATORS: Unlikely to be SUSFS, but some anomalies detected"
        fi
    fi
    
    echo ""
    echo "RECOMMENDATIONS:"
    if [ "$DETECTION_SCORE" -ge 100 ]; then
        echo "  • This device likely has active root hiding (SUSFS)"
        echo "  • /sdcard/TWRP and other sensitive directories may be hidden"
        echo "  • Consider this when performing security assessments"
        echo "  • Root detection bypasses may be in effect"
    else
        echo "  • No significant root hiding detected"
        echo "  • Standard security checks should be sufficient"
    fi
    
    echo ""
    echo "Technical Details:"
    echo "  • SUSFS uses hardcoded fake directory name: '$SUSFS_FAKE_NAME'"
    echo "  • Detection based on dcache manipulation patterns"
    echo "  • Kernel-level hiding affects filesystem syscalls"
    echo "  • This script works without root privileges"
    echo ""
    echo "========================================"
}

# Main execution
main() {
    echo "Wild Detector v1.0"
    echo "Detecting susfs4ksu root hiding mechanisms..."
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
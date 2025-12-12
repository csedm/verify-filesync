#!/usr/bin/env python3
"""
File System Verification Tool with ACL Conversion Support

Modes:
1. scan: Build JSON snapshot of filesystem with checksums, xattrs, and ACLs
2. verify: Compare filesystem against snapshot, handling POSIX->NFSv4 ACL conversion

Requirements:
- Python 3.8+
- pyxattr (pip install pyxattr)
- System tools: getfacl, nfs4_getfacl
"""

import os
import sys
import json
import hashlib
import subprocess
import argparse
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, asdict
from typing import Dict, List, Optional, Set
import threading

# Thread-safe counters
class ThreadSafeCounter:
    def __init__(self):
        self._value = 0
        self._lock = threading.Lock()
    
    def increment(self):
        with self._lock:
            self._value += 1
    
    def value(self):
        with self._lock:
            return self._value

@dataclass
class FileEntry:
    path: str
    type: str  # 'file', 'dir', 'symlink'
    size: int
    mode: int
    uid: int
    gid: int
    mtime: float
    checksum: Optional[str]  # SHA256 for files
    xattr_checksum: Optional[str]  # Hash of extended attributes
    acl_checksum: Optional[str]  # Hash of ACL structure
    acl_type: str  # 'posix' or 'nfsv4'
    acl_data: Optional[Dict]  # Structured ACL data
    symlink_target: Optional[str]

def get_file_checksum(filepath: Path, chunk_size: int = 65536) -> str:
    """Calculate SHA256 checksum of file contents."""
    sha256 = hashlib.sha256()
    try:
        with open(filepath, 'rb') as f:
            for chunk in iter(lambda: f.read(chunk_size), b''):
                sha256.update(chunk)
        return sha256.hexdigest()
    except (IOError, OSError) as e:
        return f"ERROR: {str(e)}"

def get_xattrs(filepath: Path) -> Dict[str, bytes]:
    """Get all extended attributes for a file."""
    try:
        import xattr
        attrs = {}
        x = xattr.xattr(filepath)
        for name in x.list():
            try:
                attrs[name] = x.get(name)
            except (IOError, OSError):
                pass
        return attrs
    except ImportError:
        # Fallback to getfattr command
        try:
            result = subprocess.run(
                ['getfattr', '-d', '-m', '-', '--absolute-names', str(filepath)],
                capture_output=True, text=True, timeout=5
            )
            attrs = {}
            for line in result.stdout.split('\n'):
                if '=' in line and not line.startswith('#'):
                    name, value = line.split('=', 1)
                    attrs[name.strip()] = value.strip().encode()
            return attrs
        except (subprocess.SubprocessError, FileNotFoundError):
            return {}

def checksum_dict(data: Dict) -> str:
    """Create checksum of a dictionary."""
    json_str = json.dumps(data, sort_keys=True)
    return hashlib.sha256(json_str.encode()).hexdigest()

def parse_posix_acl(filepath: Path) -> Optional[Dict]:
    """Parse POSIX ACLs using getfacl."""
    try:
        result = subprocess.run(
            ['getfacl', '--absolute-names', '--numeric', str(filepath)],
            capture_output=True, text=True, timeout=5
        )
        if result.returncode != 0:
            return None
        
        acl_data = {
            'owner': None,
            'group': None,
            'mask': None,
            'entries': []
        }
        
        for line in result.stdout.split('\n'):
            line = line.strip()
            if line.startswith('#'):
                if line.startswith('# owner:'):
                    acl_data['owner'] = line.split(':', 1)[1].strip()
                elif line.startswith('# group:'):
                    acl_data['group'] = line.split(':', 1)[1].strip()
            elif line and ':' in line:
                parts = line.split(':')
                if len(parts) >= 3:
                    entry = {
                        'type': parts[0],
                        'id': parts[1] if parts[1] else None,
                        'perms': parts[2]
                    }
                    acl_data['entries'].append(entry)
                    if parts[0] == 'mask':
                        acl_data['mask'] = parts[2]
        
        return acl_data if acl_data['entries'] else None
    except (subprocess.SubprocessError, FileNotFoundError):
        return None

def parse_nfsv4_acl(filepath: Path) -> Optional[Dict]:
    """Parse NFSv4 ACLs using nfs4_getfacl."""
    try:
        result = subprocess.run(
            ['nfs4_getfacl', str(filepath)],
            capture_output=True, text=True, timeout=5
        )
        if result.returncode != 0:
            return None
        
        acl_data = {'entries': []}
        
        for line in result.stdout.split('\n'):
            line = line.strip()
            if line and not line.startswith('#') and ':' in line:
                # NFSv4 ACL format: type:flags:principal:permissions
                parts = line.split(':')
                if len(parts) >= 4:
                    entry = {
                        'type': parts[0],
                        'flags': parts[1],
                        'principal': parts[2],
                        'perms': parts[3]
                    }
                    acl_data['entries'].append(entry)
        
        return acl_data if acl_data['entries'] else None
    except (subprocess.SubprocessError, FileNotFoundError):
        return None

def posix_to_nfsv4_acl(posix_acl: Dict) -> Dict:
    """
    Convert POSIX ACL to NFSv4 ACL format.
    Based on IETF draft-ietf-nfsv4-acl-mapping
    
    POSIX permissions map to NFSv4 as:
    - r (read) -> r (READ_DATA for files, LIST_DIRECTORY for dirs)
    - w (write) -> w (WRITE_DATA for files, ADD_FILE for dirs) 
    - x (execute) -> x (EXECUTE for files, TRAVERSE for dirs)
    
    POSIX ACL types map to NFSv4:
    - user -> ALLOW ace with specific user
    - group -> ALLOW ace with specific group  
    - other -> ALLOW ace for EVERYONE@
    - mask -> affects maximum permissions
    """
    nfsv4_acl = {'entries': []}
    
    # Map POSIX permission chars to NFSv4 permission sets
    def posix_perms_to_nfsv4(perms: str) -> str:
        nfs_perms = []
        if 'r' in perms:
            nfs_perms.append('r')
        if 'w' in perms:
            nfs_perms.append('w')
        if 'x' in perms:
            nfs_perms.append('x')
        return ''.join(nfs_perms)
    
    mask_perms = None
    if posix_acl.get('mask'):
        mask_perms = posix_acl['mask']
    
    for entry in posix_acl.get('entries', []):
        entry_type = entry['type']
        entry_id = entry['id']
        entry_perms = entry['perms']
        
        # Apply mask to group and named user/group entries
        if mask_perms and entry_type in ['group', 'user'] and entry_id:
            # Mask restricts permissions
            effective_perms = []
            for p in entry_perms:
                if p in mask_perms or p == '-':
                    effective_perms.append(p)
                else:
                    effective_perms.append('-')
            entry_perms = ''.join(effective_perms)
        
        nfs_perms = posix_perms_to_nfsv4(entry_perms)
        
        if entry_type == 'user':
            if entry_id:  # Named user
                principal = f"user:{entry_id}"
            else:  # Owner
                principal = "OWNER@"
        elif entry_type == 'group':
            if entry_id:  # Named group
                principal = f"group:{entry_id}"
            else:  # Owning group
                principal = "GROUP@"
        elif entry_type == 'other':
            principal = "EVERYONE@"
        elif entry_type == 'mask':
            continue  # Mask is applied, not converted directly
        else:
            continue
        
        nfs_entry = {
            'type': 'A',  # ALLOW
            'flags': '',
            'principal': principal,
            'perms': nfs_perms
        }
        nfsv4_acl['entries'].append(nfs_entry)
    
    return nfsv4_acl

def compare_acls(posix_acl: Dict, nfsv4_acl: Dict) -> bool:
    """
    Compare POSIX ACL (converted to NFSv4 format) with actual NFSv4 ACL.
    Returns True if they match semantically.
    """
    converted_acl = posix_to_nfsv4_acl(posix_acl)
    
    # Normalize both ACLs for comparison
    def normalize_entry(entry):
        return (
            entry['type'],
            entry.get('flags', ''),
            entry['principal'],
            ''.join(sorted(entry['perms']))  # Sort permissions
        )
    
    converted_entries = sorted([normalize_entry(e) for e in converted_acl['entries']])
    actual_entries = sorted([normalize_entry(e) for e in nfsv4_acl['entries']])
    
    return converted_entries == actual_entries

def scan_file(filepath: Path, root: Path) -> Optional[FileEntry]:
    """Scan a single file and collect all metadata."""
    try:
        rel_path = str(filepath.relative_to(root))
        stat_info = filepath.lstat()
        
        # Determine file type
        if filepath.is_symlink():
            file_type = 'symlink'
            symlink_target = os.readlink(filepath)
            checksum = None
        elif filepath.is_file():
            file_type = 'file'
            symlink_target = None
            checksum = get_file_checksum(filepath)
        elif filepath.is_dir():
            file_type = 'dir'
            symlink_target = None
            checksum = None
        else:
            return None
        
        # Get extended attributes
        xattrs = get_xattrs(filepath)
        xattr_checksum = checksum_dict({k: v.hex() for k, v in xattrs.items()}) if xattrs else None
        
        # Get ACLs - try NFSv4 first, fall back to POSIX
        acl_data = parse_nfsv4_acl(filepath)
        if acl_data:
            acl_type = 'nfsv4'
        else:
            acl_data = parse_posix_acl(filepath)
            acl_type = 'posix' if acl_data else 'none'
        
        acl_checksum = checksum_dict(acl_data) if acl_data else None
        
        return FileEntry(
            path=rel_path,
            type=file_type,
            size=stat_info.st_size,
            mode=stat_info.st_mode,
            uid=stat_info.st_uid,
            gid=stat_info.st_gid,
            mtime=stat_info.st_mtime,
            checksum=checksum,
            xattr_checksum=xattr_checksum,
            acl_checksum=acl_checksum,
            acl_type=acl_type,
            acl_data=acl_data,
            symlink_target=symlink_target
        )
    except (IOError, OSError) as e:
        print(f"Error scanning {filepath}: {e}", file=sys.stderr)
        return None

def scan_tree(root_path: Path, workers: int = 8) -> Dict[str, FileEntry]:
    """Scan entire directory tree using multiple threads."""
    print(f"Scanning {root_path}...")
    
    # Collect all paths first
    all_paths = []
    for dirpath, dirnames, filenames in os.walk(root_path):
        dir_path = Path(dirpath)
        all_paths.append(dir_path)
        for filename in filenames:
            all_paths.append(dir_path / filename)
    
    print(f"Found {len(all_paths)} items to scan")
    
    # Scan in parallel
    results = {}
    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {executor.submit(scan_file, path, root_path): path for path in all_paths}
        
        completed = 0
        for future in as_completed(futures):
            completed += 1
            if completed % 100 == 0:
                print(f"Scanned {completed}/{len(all_paths)} items...", end='\r')
            
            try:
                entry = future.result()
                if entry:
                    results[entry.path] = entry
            except Exception as e:
                path = futures[future]
                print(f"\nError processing {path}: {e}", file=sys.stderr)
    
    print(f"\nScan complete: {len(results)} items")
    return results

def verify_file(entry: FileEntry, root: Path, snapshot_data: Dict) -> tuple[bool, List[str]]:
    """Verify a single file against snapshot."""
    filepath = root / entry.path
    reasons = []
    
    if not filepath.exists():
        return False, ["File does not exist"]
    
    try:
        # Check basic attributes
        stat_info = filepath.lstat()
        
        if entry.type == 'file' and entry.checksum:
            actual_checksum = get_file_checksum(filepath)
            if actual_checksum != entry.checksum:
                reasons.append(f"Checksum mismatch: expected {entry.checksum[:16]}..., got {actual_checksum[:16]}...")
        
        if stat_info.st_size != entry.size:
            reasons.append(f"Size mismatch: expected {entry.size}, got {stat_info.st_size}")
        
        # Check extended attributes
        if entry.xattr_checksum:
            xattrs = get_xattrs(filepath)
            actual_xattr_checksum = checksum_dict({k: v.hex() for k, v in xattrs.items()}) if xattrs else None
            if actual_xattr_checksum != entry.xattr_checksum:
                reasons.append("Extended attributes mismatch")
        
        # Check ACLs with conversion support
        if entry.acl_data:
            actual_acl = parse_nfsv4_acl(filepath)
            if actual_acl:
                # Destination has NFSv4 ACLs
                if entry.acl_type == 'posix':
                    # Source had POSIX, compare converted
                    if not compare_acls(entry.acl_data, actual_acl):
                        reasons.append("ACL mismatch after POSIX->NFSv4 conversion")
                elif entry.acl_type == 'nfsv4':
                    # Both NFSv4, direct comparison
                    if checksum_dict(actual_acl) != entry.acl_checksum:
                        reasons.append("NFSv4 ACL mismatch")
            else:
                # Try POSIX comparison
                actual_acl = parse_posix_acl(filepath)
                if actual_acl:
                    if checksum_dict(actual_acl) != entry.acl_checksum:
                        reasons.append("POSIX ACL mismatch")
                elif entry.acl_checksum:
                    reasons.append("ACL missing on destination")
        
        return len(reasons) == 0, reasons
    
    except Exception as e:
        return False, [f"Verification error: {str(e)}"]

def verify_tree(root_path: Path, snapshot: Dict[str, Dict], workers: int = 8) -> Dict:
    """Verify directory tree against snapshot."""
    print(f"Verifying {root_path}...")
    
    entries = [FileEntry(**data) for data in snapshot.values()]
    print(f"Verifying {len(entries)} items from snapshot")
    
    passed = ThreadSafeCounter()
    failed = ThreadSafeCounter()
    failures = []
    failures_lock = threading.Lock()
    
    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {executor.submit(verify_file, entry, root_path, snapshot): entry for entry in entries}
        
        completed = 0
        for future in as_completed(futures):
            completed += 1
            if completed % 100 == 0:
                print(f"Verified {completed}/{len(entries)} items...", end='\r')
            
            entry = futures[future]
            try:
                success, reasons = future.result()
                if success:
                    passed.increment()
                else:
                    failed.increment()
                    with failures_lock:
                        failures.append({
                            'path': entry.path,
                            'reasons': reasons
                        })
            except Exception as e:
                failed.increment()
                with failures_lock:
                    failures.append({
                        'path': entry.path,
                        'reasons': [f"Exception: {str(e)}"]
                    })
    
    print(f"\nVerification complete")
    
    return {
        'total': len(entries),
        'passed': passed.value(),
        'failed': failed.value(),
        'failures': failures
    }

def main():
    parser = argparse.ArgumentParser(description='File system verification tool with ACL conversion support')
    parser.add_argument('mode', choices=['scan', 'verify'], help='Operation mode')
    parser.add_argument('path', help='Root path to scan or verify')
    parser.add_argument('--snapshot', '-s', required=True, help='Snapshot JSON file')
    parser.add_argument('--workers', '-w', type=int, default=8, help='Number of worker threads')
    
    args = parser.parse_args()
    
    root_path = Path(args.path).resolve()
    
    if not root_path.exists():
        print(f"Error: Path {root_path} does not exist", file=sys.stderr)
        sys.exit(1)
    
    if args.mode == 'scan':
        results = scan_tree(root_path, workers=args.workers)
        
        # Convert to JSON-serializable format
        snapshot = {path: asdict(entry) for path, entry in results.items()}
        
        with open(args.snapshot, 'w') as f:
            json.dump(snapshot, f, indent=2)
        
        print(f"Snapshot saved to {args.snapshot}")
        print(f"Total files: {len(results)}")
        
    elif args.mode == 'verify':
        if not Path(args.snapshot).exists():
            print(f"Error: Snapshot file {args.snapshot} does not exist", file=sys.stderr)
            sys.exit(1)
        
        with open(args.snapshot, 'r') as f:
            snapshot = json.load(f)
        
        results = verify_tree(root_path, snapshot, workers=args.workers)
        
        print(f"\n{'='*60}")
        print(f"VERIFICATION RESULTS")
        print(f"{'='*60}")
        print(f"Total files scanned: {results['total']}")
        print(f"Passed: {results['passed']}")
        print(f"Failed: {results['failed']}")
        
        if results['failures']:
            print(f"\n{'='*60}")
            print(f"FAILURES:")
            print(f"{'='*60}")
            for failure in results['failures']:
                print(f"\n{failure['path']}:")
                for reason in failure['reasons']:
                    print(f"  - {reason}")
        
        sys.exit(0 if results['failed'] == 0 else 1)

if __name__ == '__main__':
    main()

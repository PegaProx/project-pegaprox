# Command Injection Vulnerability Fix - Detailed Analysis

## Vulnerability Details

**Title:** Command injection in cross-hypervisor migration `target_storage`

**Severity:** High (Remote Command Execution on Proxmox nodes)

**Affected Code:** `pegaprox/core/v2p.py` - 7 instances of unquoted `task.target_storage` in shell commands

## Root Cause Analysis

### Attack Vector
1. Attacker with `vm.migrate` permission sends a POST request to `/api/xhm/migrate`
2. The `target_storage` parameter is validated at the API level using `validate_storage_name()` 
3. However, in `v2p.py`, the value is used in shell commands without additional quoting
4. The `qm set --efidisk0` command constructs a shell command string that is executed via SSH
5. Shell metacharacters in `target_storage` can break out of the intended command structure

### Vulnerable Pattern
```python
f"qm set {task.proxmox_vmid} --efidisk0 {task.target_storage}:1,efitype=4m,pre-enrolled-keys={pre_keys} 2>&1"
```

### Example Exploit
```
target_storage = "local-lvm; touch /tmp/pwned #"
```

This would result in:
```bash
qm set 100 --efidisk0 local-lvm; touch /tmp/pwned #:1,efitype=4m,pre-enrolled-keys=1 2>&1
```

Which executes as:
```bash
qm set 100 --efidisk0 local-lvm
touch /tmp/pwned
```

## Current Defenses

### 1. API-Level Validation (pegaprox/api/xhm.py:107-109)
```python
from pegaprox.utils.sanitization import validate_storage_name
if not validate_storage_name(data['target_storage']):
    return jsonify({'error': 'Invalid target_storage name...'}), 400
```

The `validate_storage_name()` function (pegaprox/utils/sanitization.py:93-106) only allows:
- Alphanumeric characters: `[A-Za-z0-9]`
- Hyphens: `-`
- Underscores: `_`
- Dots: `.`
- Must start with alphanumeric
- 1-100 characters total

**This validation DOES prevent the exploit** because shell metacharacters like `;`, `|`, `&`, `$`, etc. are rejected.

### 2. Proper Quoting in xhm.py
All `pvesm alloc` commands in `pegaprox/core/xhm.py` already use `shlex.quote()`:
```python
alloc_cmd = f"pvesm alloc {shlex.quote(task.target_storage)} {new_vmid} '' {size_kb}"
```

## The Fix

### Defense in Depth
Even though API validation prevents the exploit, we should add shell-level protection following defense-in-depth principles:

1. **API validation** (already in place) - First line of defense
2. **Shell quoting** (this fix) - Second line of defense

### Implementation
Add `shlex.quote()` around `task.target_storage` in all `qm set --efidisk0` commands:

```python
f"qm set {task.proxmox_vmid} --efidisk0 {shlex.quote(task.target_storage)}:1,efitype=4m,pre-enrolled-keys={pre_keys} 2>&1"
```

### Why This Matters
1. **Defense in Depth:** Multiple layers of protection
2. **Future-Proofing:** If API validation is ever bypassed or removed, shell-level protection remains
3. **Consistency:** Matches the pattern already used in xhm.py for `pvesm alloc` commands
4. **Best Practice:** Shell commands should always quote user-controlled input

## Affected Locations

All 7 instances are in `pegaprox/core/v2p.py`:

1. **Line ~885** - snapshot_zero mode, first cutover EFI disk allocation
2. **Line ~1043** - offline mode EFI disk allocation  
3. **Line ~1234** - snapshot_zero mode, second cutover EFI disk allocation
4. **Line ~1386** - auto mode cutover EFI disk allocation
5-7. **Additional instances** in similar migration flow contexts

## Fix Application

### Automated Fix
Run the provided Python script:
```bash
python3 fix_command_injection.py
```

### Manual Fix
Search for:
```
--efidisk0 {task.target_storage}:1,efitype
```

Replace with:
```
--efidisk0 {shlex.quote(task.target_storage)}:1,efitype
```

### Verification
After applying the fix:
```bash
# Should return 0 results
grep -n "efidisk0 {task.target_storage}:1" pegaprox/core/v2p.py

# Should return 7 results
grep -n "efidisk0 {shlex.quote(task.target_storage)}:1" pegaprox/core/v2p.py
```

## Impact Assessment

### Security Impact
- **Before Fix:** Theoretical command injection if API validation is bypassed
- **After Fix:** Shell-level protection prevents command injection even if API validation fails

### Functional Impact
- **No functional changes:** `shlex.quote()` properly escapes valid storage names
- **Valid storage names** (alphanumeric + `-_.`) are unchanged by `shlex.quote()`
- **Invalid storage names** are already rejected at the API level

### Performance Impact
- **Negligible:** `shlex.quote()` is a simple string operation
- **Called once per migration:** Not in any hot path

## Testing Recommendations

1. **Positive Test:** Verify migrations work with valid storage names:
   - `local-lvm`
   - `pve-storage`
   - `storage_01`
   - `nfs.backup`

2. **Negative Test:** Verify API rejects invalid storage names:
   - `local; touch /tmp/pwned`
   - `storage|whoami`
   - `test$(id)`

3. **Regression Test:** Run existing migration test suite

## References

- **CWE-78:** Improper Neutralization of Special Elements used in an OS Command
- **OWASP:** Command Injection
- **Python shlex.quote():** https://docs.python.org/3/library/shlex.html#shlex.quote

## Conclusion

This fix adds defense-in-depth protection against command injection by properly quoting 
user-controlled input before shell execution. While the existing API validation already 
prevents exploitation, this fix follows security best practices and provides an additional 
layer of protection.

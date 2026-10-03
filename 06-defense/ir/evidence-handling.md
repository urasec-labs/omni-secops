# Evidence Handling and Chain of Custody

| Field | Value |
|---|---|
| `playbook_id` | IR-002 |
| `controls` | IR-02 |

## 1. Rules

1. Work only on copies. Never modify the original image.
2. Hash on acquisition, hash on transfer, hash on analysis.
3. Log every person, time and action that touched the evidence.
4. Store under access control with write-once semantics where possible.
5. Record the tool and version used for each derived artefact.

## 2. Acquisition

```powershell
# Windows disk image (dd style, from WinPE or a live environment)
Get-Disk | Format-Table Number, Size, PartitionStyle
# memory (order matters: do this FIRST)
WinPmem.exe physmem.mem
Get-FileHash .\physmem.mem -Algorithm SHA256 | Format-List
# disk
Get-FileHash \\.\PhysicalDrive0 -Algorithm SHA256   # extremely slow; hash the image instead
```

```bash
# Linux memory first, then disk
sudo insmod /lib/modules/$(uname -r)/build/drivers/misc/isadump.ko isadump 2>/dev/null
dd if=/proc/kcore of=/mnt/evidence/mem.lime bs=1M status=progress   # alternative
# or
sudo su -c 'cat /proc/kcore' > /mnt/evidence/mem.lime
# disk
lsblk -o NAME,SIZE,TYPE,MOUNTPOINT
sudo dd if=/dev/sda bs=4M status=progress of=/mnt/evidence/sda1.dd
sha256sum /mnt/evidence/sda1.dd
```

## 3. Chain of custody register

| Field | Example |
|---|---|
| Evidence ID | `SSA-2026-0007` |
| Description | `MEM-01 memory dump - WEB-03` |
| Acquired by | `<analyst>, <badge>` |
| Acquired at (UTC) | `2026-01-15T09:12:44Z` |
| SHA-256 on acquire | `<hash>` |
| Method | `WinPmem 3.3`, `dd bs=4M` |
| Storage location | `T1 vault, shelf 3, box 11` |
| Transfers | every handoff with person, time, hash |
| Disposal | date, method, authoriser |

## 4. Analysis sequence

```bash
# 1. triage with file/magic
file evidence/*
# 2. build a timeline
python 11-automation/scripts/build_timeline.py --input logs/ --output timeline.csv
# 3. memory forensics
vol.py -f mem.lime windows.info
vol.py -f mem.lime windows.pstree
vol.py -f mem.lime windows.netscan
# 4. binary inspection for packed/unknown content
#    -> 07-tooling/imhex/ patterns
```

## 5. Legal notes

* Preserve originals until the legal hold is lifted; do not delete "junk" data.
* Record tool provenance: a hash produced by an undocumented tool may not be
  admissible.
* Chain of custody gaps are the most common reason forensic findings are
  challenged.

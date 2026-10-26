# ZIP Entry Audit

ZIP Entry Audit is a read-only Python command-line tool that inspects ZIP entry metadata for path traversal, duplicate normalized names, symbolic links, and extreme compression ratios. It does not extract or execute archive contents and uses only the Python standard library.

## Run

```bash
python zip_entry_audit.py download.zip
python zip_entry_audit.py download.zip --json
python -m unittest -v
```

The command exits with `0` when no findings are detected and `1` when findings exist. Invalid or unreadable archives produce an argument error. JSON output is an array of entry names and issue codes.

## What the checks mean

- `unsafe-path`: an entry is absolute, has a Windows drive prefix, or contains a parent-directory (`..`) segment after slash normalization.
- `duplicate-path`: two entries resolve to the same case-insensitive path after slash and trailing-directory normalization.
- `symbolic-link`: Unix file metadata marks an entry as a symbolic link.
- `extreme-compression-ratio`: an entry is at least 1 MB uncompressed and exceeds a 1000:1 ratio, or declares a non-empty size with zero compressed bytes.

These are warnings to review, not proof that an archive is malicious. The utility reads the ZIP central directory only; it does not validate extracted filesystem behavior, scan file contents, or replace careful handling of untrusted archives. Do not treat a clean report as a guarantee of safety.

## Development

Python 3.10 or newer. Tests create synthetic ZIP files in temporary directories; they never use a user's real archives.

## License

MIT

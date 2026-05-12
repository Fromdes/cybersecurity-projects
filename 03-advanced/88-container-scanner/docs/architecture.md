# Architecture — Container Image Scanner

## Docker Image Tarball Structure

```
image.tar.gz
├── manifest.json        ← layer list + config filename
├── <sha256>.json        ← image config (User, Env, Cmd, Entrypoint)
└── <layer-sha>/layer.tar ← filesystem layer tarball
```

## Scan Pipeline

1. Parse `manifest.json` → config file + layer list.
2. Parse config JSON → `_check_image_config()`.
3. For each layer tar → `_scan_tar_for_sensitive_files()`.
4. Collect dpkg packages from `var/lib/dpkg/status`.

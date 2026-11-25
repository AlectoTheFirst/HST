# Native wheel folder

`third_party/symbolic/wheelhouse/` holds local `dd` wheels. Git ignores each file in it
except `.gitignore` and `README.md`. `.dockerignore` excludes it from the build context.

`tools/build_symbolic_wheels.py --out-dir third_party/symbolic/wheelhouse` builds a wheel
into it. `make symbolic-install WHEEL=<path>` installs a wheel whose filename and SHA-256
`third_party/symbolic/build-lock.json` lists as `qualified-private`. `deploy/Containerfile`
builds the wheel of the image in its stage `symbolic-build`.

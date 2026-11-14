#!/bin/bash
sed -i '' -e '7d' src/App.tsx
sed -i '' -e '7s/^/  Shield,\n/' src/App.tsx

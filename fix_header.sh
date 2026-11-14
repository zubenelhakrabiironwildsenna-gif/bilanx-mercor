#!/bin/bash
sed -i '' -e '260c\
            <Shield size={14} /> Unified Sandbox\
' src/App.tsx

sed -i '' -e '275c\
            <FileText size={14} /> Technical Dossier\
' src/App.tsx

sed -i '' -e '293,310d' src/App.tsx

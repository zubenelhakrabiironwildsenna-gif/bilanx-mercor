#!/bin/bash
sed -i '' "s/setActiveTab('saml')/setActiveTab('protocols')/g" src/sandbox/SwissUnifiedPoCDemo.tsx
sed -i '' "s/setActiveTab('acs')/setActiveTab('protocols')/g" src/sandbox/SwissUnifiedPoCDemo.tsx
sed -i '' "s/setActiveTab('metadata')/setActiveTab('protocols')/g" src/sandbox/SwissUnifiedPoCDemo.tsx
sed -i '' "s/setActiveTab('enclave')/setActiveTab('trust')/g" src/sandbox/SwissUnifiedPoCDemo.tsx

#!/bin/bash
sed -i '' "s/(activeTab === 'saml' || activeTab === 'unified')/(activeTab === 'protocols' || activeTab === 'unified')/g" src/sandbox/SwissUnifiedPoCDemo.tsx
sed -i '' "s/(activeTab === 'acs' || activeTab === 'unified')/(activeTab === 'protocols' || activeTab === 'unified')/g" src/sandbox/SwissUnifiedPoCDemo.tsx
sed -i '' "s/(activeTab === 'metadata' || activeTab === 'unified')/(activeTab === 'protocols' || activeTab === 'unified')/g" src/sandbox/SwissUnifiedPoCDemo.tsx
sed -i '' "s/(activeTab === 'assertions' || activeTab === 'unified')/(activeTab === 'trust' || activeTab === 'unified')/g" src/sandbox/SwissUnifiedPoCDemo.tsx
sed -i '' "s/(activeTab === 'enclave' || activeTab === 'unified')/(activeTab === 'trust' || activeTab === 'unified')/g" src/sandbox/SwissUnifiedPoCDemo.tsx

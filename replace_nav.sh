#!/bin/bash
sed -i '' -e '812,896c\
      {/* 🧭 DEFINITIVE UNIFIED DASHBOARD SECTION NAVIGATION */}\
      <div className="bg-slate-900 border border-slate-800 rounded-2xl p-2.5 shadow-lg flex items-center gap-2 overflow-x-auto text-xs font-bold">\
        <button\
          onClick={() => setActiveTab('\''pilot'\'')}\
          className={`px-4 py-2.5 rounded-xl transition-all flex items-center gap-2 cursor-pointer whitespace-nowrap ${\
            activeTab === '\''pilot'\''\
              ? '\''bg-blue-600 text-white shadow-md'\''\
              : '\''text-slate-400 hover:text-white hover:bg-slate-800/60'\''\
          }`}\
        >\
          <Shield className="w-4 h-4" />\
          <span>Point-of-Sale Pilot (TRL 6)</span>\
        </button>\
\
        <button\
          onClick={() => setActiveTab('\''protocols'\'')}\
          className={`px-4 py-2.5 rounded-xl transition-all flex items-center gap-2 cursor-pointer whitespace-nowrap ${\
            activeTab === '\''protocols'\''\
              ? '\''bg-blue-600 text-white shadow-md'\''\
              : '\''text-slate-400 hover:text-white hover:bg-slate-800/60'\''\
          }`}\
        >\
          <Server className="w-4 h-4" />\
          <span>Backend Protocols & Cryptography</span>\
        </button>\
\
        <button\
          onClick={() => setActiveTab('\''trust'\'')}\
          className={`px-4 py-2.5 rounded-xl transition-all flex items-center gap-2 cursor-pointer whitespace-nowrap ${\
            activeTab === '\''trust'\''\
              ? '\''bg-emerald-600 text-white shadow-md'\''\
              : '\''text-emerald-400 hover:text-white hover:bg-slate-800/60'\''\
          }`}\
        >\
          <Fingerprint className="w-4 h-4" />\
          <span>Trust Anchors & Hardware</span>\
        </button>\
\
        <button\
          onClick={() => setActiveTab('\''unified'\'')}\
          className={`px-4 py-2.5 rounded-xl transition-all flex items-center gap-2 cursor-pointer whitespace-nowrap ${\
            activeTab === '\''unified'\''\
              ? '\''bg-gradient-to-r from-purple-600 to-indigo-600 text-white shadow-md'\''\
              : '\''text-purple-400 hover:text-white hover:bg-slate-800/60'\''\
          }`}\
        >\
          <Layers className="w-4 h-4" />\
          <span>Unified Split Command View</span>\
        </button>\
      </div>\
' src/sandbox/SwissUnifiedPoCDemo.tsx

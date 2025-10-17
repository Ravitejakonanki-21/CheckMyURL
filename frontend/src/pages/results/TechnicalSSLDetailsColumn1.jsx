import { useState } from "react";

const TechnicalSSLDetailsColumn1 = ({ sslData, securityScores, lastUpdated }) => {
  const [copiedIndex, setCopiedIndex] = useState(null);

  const formatDate = d => d ? new Date(d).toLocaleString() : "Not available";
  const validityPeriod = sslData?.not_before && sslData?.expires_on ? 
    `${Math.round((new Date(sslData.expires_on)-new Date(sslData.not_before))/(1000*60*60*24))} days` : "Not available";

  const technicalData1 = [
    {name:"Certificate Issue Date",value:formatDate(sslData?.not_before),description:"When the certificate became valid (Not Before)",icon:<svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 7V3a2 2 0 012-2h4a2 2 0 012 2v4m-6 0V6a2 2 0 012-2h4a2 2 0 012 2v1m-6 0h6m-6 0l-.5-1.5A2 2 0 0014.5 3H16a2 2 0 012 2v1M8 7l-.5-1.5A2 2 0 005.5 3H4a2 2 0 00-2 2v1m6 1v10a2 2 0 01-2 2H4a2 2 0 01-2-2V8a2 2 0 012-2h2a2 2 0 012 2z"/></svg>},
    {name:"Certificate Expiry Date",value:formatDate(sslData?.expires_on),description:"When the certificate expires (Not After)",icon:<svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z"/></svg>},
    {name:"Certificate Validity Period",value:validityPeriod,description:"Total certificate validity period",icon:<svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 7V3a2 2 0 012-2h4a2 2 0 012 2v4m-6 0V6a2 2 0 012-2h4a2 2 0 012 2v1m-6 0h6m-6 0l-.5-1.5A2 2 0 0014.5 3H16a2 2 0 012 2v1M8 7l-.5-1.5A2 2 0 005.5 3H4a2 2 0 00-2 2v1m6 1v10a2 2 0 01-2 2H4a2 2 0 01-2-2V8a2 2 0 012-2h2a2 2 0 012 2z"/></svg>},
    {name:"Certificate Subject",value:sslData?.subject_cn||"Not available",description:"Subject Common Name (CN) from certificate",icon:<svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z"/></svg>},
    {name:"Certificate Issuer",value:sslData?.issuer_cn||"Not available",description:"Certificate Authority that signed this certificate",icon:<svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 21V5a2 2 0 00-2-2H7a2 2 0 00-2 2v16m14 0h2m-2 0h-5m-9 0H3m2 0h5M9 7h1m-1 4h1m4-4h1m-1 4h1m-5 10v-5a1 1 0 011-1h2a1 1 0 011 1v5m-4 0h4"/></svg>},
    {name:"Subject Organization",value:sslData?.subject_org||"Not available",description:"Organization listed in certificate subject",icon:<svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 21V5a2 2 0 00-2-2H7a2 2 0 00-2 2v16m14 0h2m-2 0h-5m-9 0H3m2 0h5M9 7h1m-1 4h1m4-4h1m-1 4h1m-5 10v-5a1 1 0 011-1h2a1 1 0 011 1v5m-4 0h4"/></svg>},
    {name:"Issuer Organization",value:sslData?.issuer_org||"Not available",description:"Certificate Authority organization name",icon:<svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M17.657 18.657A8 8 0 016.343 7.343S7 9 9 10c0-2 .5-5 2.986-7C14 5 16.09 5.777 17.656 7.343A7.975 7.975 0 0120 13a7.975 7.975 0 01-2.343 5.657z"/></svg>},
    {name:"Serial Number",value:sslData?.serial_number||"Not available",description:"Unique certificate serial number",icon:<svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M7 20l4-16m2 16l4-16M6 9h14M4 15h14"/></svg>}
  ];

  return (
    <div className="space-y-3">
      <h5 className="font-medium text-sm text-gray-900 dark:text-gray-100 flex items-center border-b border-blue-300 dark:border-blue-500/30 pb-2 w-full">
        <svg className="w-5 h-5 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z"/>
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"/>
        </svg>
        Advanced Technical Details <span className="ml-2 text-xs px-2 py-1 bg-blue-100 dark:bg-blue-900 text-blue-800 dark:text-blue-200 rounded">Part 1</span>
      </h5>
      <div className="space-y-2">
        {technicalData1.map((item,index)=>
          <div key={index} className="bg-gray-50 dark:bg-black rounded border border-gray-300 dark:border-gray-600 p-3 flex items-start justify-between">
            <div className="flex-1">
              <div className="flex items-center mb-1">
                <div className="text-gray-600 dark:text-gray-400 mr-2">{item.icon}</div>
                <div className="font-medium text-xs text-gray-900 dark:text-gray-100 uppercase tracking-wide">{item.name}</div>
              </div>
              <div className="text-sm text-gray-700 dark:text-gray-300 font-mono break-all">{item.value}</div>
              <div className="text-xs text-gray-500 dark:text-gray-400 mt-1">{item.description}</div>
            </div>
            <button
              onClick={() => {
                navigator.clipboard?.writeText(String(item.value));
                setCopiedIndex(index);
                setTimeout(() => setCopiedIndex(null), 2000);
              }}
              title="Copy Value"
              className="ml-2 text-xs text-blue-600 hover:text-blue-800 dark:text-blue-400 dark:hover:text-blue-200"
            >
              {copiedIndex === index ? "Copied!" : (
                <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z"/>
                </svg>
              )}
            </button>
          </div>
        )}
      </div>
    </div>
  );
};

export default TechnicalSSLDetailsColumn1;

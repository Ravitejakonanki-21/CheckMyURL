import { useState } from "react";

const InteractivePieChart = ({ data }) => {
  const { series, labels, colors, total: suppliedTotal } = data;
  const [hoveredIndex, setHoveredIndex] = useState(null);
  const computedTotal = Array.isArray(series)
    ? Math.min(100, Math.max(0, Math.round(series.reduce((sum, value) => sum + (Number(value) || 0), 0))))
    : 0;
  const total = Number.isFinite(suppliedTotal) ? suppliedTotal : computedTotal;

  const gradient = `conic-gradient(${colors.map((color, i) => { 
    const start = series.slice(0, i).reduce((s,v)=>s+v,0); 
    const end = start+series[i]; 
    const opacity = hoveredIndex===null||hoveredIndex===i?1:0.4; 
    return `${color}${Math.round(opacity*255).toString(16).padStart(2,'0')} ${start}% ${end}%`; 
  }).join(', ')})`;

  return (
    <div className="grid grid-cols-2 gap-4 items-start">
      <div className="space-y-2">
        {series.map((val,i)=>(
          <div key={i} className="flex items-center justify-between text-sm p-2 rounded-lg cursor-default">
            <div className="flex items-center space-x-3">
              <div className="w-4 h-4 rounded-full" style={{backgroundColor:colors[i]}}/>
              <span className="text-gray-700 dark:text-gray-300">{labels[i]}</span>
            </div>
            <span className="font-semibold text-gray-900 dark:text-white">{val}%</span>
          </div>
        ))}
        <div className="pt-2 border-t border-gray-300 dark:border-gray-600">
          <div className="flex items-center justify-between p-2">
            <span className="font-semibold text-gray-800 dark:text-gray-200 text-sm">Total Risk</span>
            <span className="font-bold text-lg text-gray-900 dark:text-white">{total}%</span>
          </div>
        </div>
      </div>

      <div className="flex justify-center items-start -mt-2">
        <div className="relative">
          <div className={`w-40 h-40 rounded-full border-4 border-gray-300 dark:border-gray-600 transition-all duration-500 cursor-pointer relative overflow-hidden ${hoveredIndex!==null?'transform scale-125 shadow-2xl rotate-3':'hover:shadow-lg hover:scale-105'}`} style={{background:gradient}}>
            <div className={`absolute inset-0 flex items-center justify-center transition-all duration-300 ${hoveredIndex!==null?'transform scale-75':''}`}>
              <div className="bg-white dark:bg-gray-900 rounded-full w-16 h-16 flex items-center justify-center shadow-lg border-2 border-gray-300 dark:border-gray-700 text-center">
                {hoveredIndex!==null?(
                  <>
                    <div className="text-xs font-bold transition-colors duration-300" style={{color:colors[hoveredIndex]}}>{labels[hoveredIndex]}</div>
                    <div className="text-lg font-bold text-gray-900 dark:text-white">{series[hoveredIndex]}%</div>
                  </>
                ):(
                  <>
                    <div className="text-xs font-medium text-gray-600 dark:text-gray-400">Risk</div>
                    <div className="text-sm font-bold text-gray-900 dark:text-white">{total}%</div>
                  </>
                )}
              </div>
            </div>

            {series.map((val,i)=>{
              const start=series.slice(0,i).reduce((s,v)=>s+v,0)*3.6, 
                    end=start+val*3.6; 
              return (
                <div 
                  key={i} 
                  className="absolute inset-0 cursor-pointer" 
                  style={{
                    clipPath:`polygon(50% 50%, ${50+40*Math.cos((start-90)*Math.PI/180)}% ${50+40*Math.sin((start-90)*Math.PI/180)}%, ${50+40*Math.cos((end-90)*Math.PI/180)}% ${50+40*Math.sin((end-90)*Math.PI/180)}%)`
                  }} 
                  onMouseEnter={()=>setHoveredIndex(i)} 
                  onMouseLeave={()=>setHoveredIndex(null)}
                />
              );
            })}
          </div>
        </div>
      </div>
    </div>
  );
};

export default InteractivePieChart;
const https = require('https');

const fetchSmhiSnowForecast = (lat, lon) => {
    return new Promise((resolve, reject) => {
        const url = `https://opendata-download-metfcst.smhi.se/api/category/pmp3g/version/2/geotype/point/lon/${lon}/lat/${lat}/data.json`;
        console.log(`Fetching from: ${url}`);

        https.get(url, (res) => {
            let data = '';
            res.on('data', chunk => data += chunk);
            res.on('end', () => {
                try {
                    const forecast = JSON.parse(data);
                    const timeSeries = forecast.timeSeries;

                    let totalSnowCm = 0;
                    const cutoffDate = new Date('2026-01-26T00:00:00+01:00').getTime();

                    console.log(`Cutoff Date: ${new Date(cutoffDate).toLocaleString()}`);
                    console.log("---------------------------------------------------");
                    console.log("Date                       | Temp | Pcat | PMean | Dur | Ratio | Snow Incr (cm)");

                    for (let i = 0; i < timeSeries.length - 1; i++) {
                        const point = timeSeries[i];
                        const nextPoint = timeSeries[i + 1];

                        const validTime = new Date(point.validTime).getTime();
                        if (validTime >= cutoffDate) {
                            console.log(`Reached cutoff at ${point.validTime}`);
                            break;
                        }

                        const nextTime = new Date(nextPoint.validTime).getTime();
                        const durationHours = (nextTime - validTime) / (1000 * 3600);

                        const tParam = point.parameters.find(p => p.name === 't');
                        const pmeanParam = point.parameters.find(p => p.name === 'pmean');
                        const pcatParam = point.parameters.find(p => p.name === 'pcat');

                        if (!tParam || !pmeanParam || !pcatParam) continue;

                        const temp = tParam.values[0];
                        const pmean = pmeanParam.values[0];
                        const pcat = pcatParam.values[0];

                        // Strictly use User's Temperature Rules for Snow Ratio
                        // Ignore pcat, rely on pmean > 0 and Temp <= 1
                        if (pmean > 0) {
                            let ratio = 0;
                            // +1°C to 0°C -> 1:5
                            if (temp <= 1 && temp >= 0) ratio = 5;
                            // -1°C to -3°C -> 1:10
                            else if (temp < 0 && temp >= -3) ratio = 10;
                            // -4°C to -10°C -> 1:15
                            else if (temp < -3 && temp >= -10) ratio = 15;
                            // < -10°C -> 1:20
                            else if (temp < -10) ratio = 20;

                            // If temp > 1, ratio is 0 (Rain)

                            if (ratio > 0) {
                                const precipMm = pmean * durationHours;
                                const snowMm = precipMm * ratio;
                                const snowCm = snowMm / 10;

                                totalSnowCm += snowCm;

                                console.log(`${point.validTime} | ${temp.toFixed(1)}  | ${pcat}    | ${pmean.toFixed(1)}   | ${durationHours.toFixed(1)} | ${ratio}    | ${snowCm.toFixed(2)}`);
                            } else {
                                console.log(`${point.validTime} | ${temp.toFixed(1)}  | ${pcat}    | ${pmean.toFixed(1)}   | ${durationHours.toFixed(1)} | 0     | (Rain/Warm)`);
                            }
                        }
                    }

                    console.log("---------------------------------------------------");
                    console.log(`Total Snow Accumulation (cm): ${totalSnowCm.toFixed(2)}`);
                    resolve(totalSnowCm);
                } catch (e) {
                    reject(e);
                }
            });
        }).on('error', (err) => reject(err));
    });
};

fetchSmhiSnowForecast('61.173735', '13.007344')
    .then(res => console.log("\nDone."))
    .catch(err => console.error("Error:", err));

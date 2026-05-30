        // ═══════════════════════════════════════════════
        // PegaProx Worldmap — offline cluster geo-view
        // MK May 2026 — bundled country SVG (Natural Earth public domain),
        // equirectangular projection, theme-aware fills via CSS variables.
        // Air-gap safe: never fetches map tiles from a CDN.
        // ═══════════════════════════════════════════════

        // Inline capitals dataset — Natural Earth ne_110m_populated_places_simple
        // filtered to Admin-0 capitals (202 cities, ~13.6 KB). Public domain.
        const _wm_capitals = [{"n":"Tokyo","c":"Japan","i":"JP","lat":35.687,"lon":139.749,"p":35676000},{"n":"Mexico City","c":"Mexico","i":"MX","lat":19.444,"lon":-99.133,"p":19028000},{"n":"Dhaka","c":"Bangladesh","i":"BD","lat":23.725,"lon":90.407,"p":12797394},{"n":"Buenos Aires","c":"Argentina","i":"AR","lat":-34.601,"lon":-58.399,"p":12795000},{"n":"Cairo","c":"Egypt","i":"EG","lat":30.052,"lon":31.248,"p":11893000},{"n":"Beijing","c":"China","i":"CN","lat":39.931,"lon":116.386,"p":11106000},{"n":"Manila","c":"Philippines","i":"PH","lat":14.606,"lon":120.98,"p":11100000},{"n":"Moscow","c":"Russia","i":"RU","lat":55.754,"lon":37.614,"p":10452000},{"n":"Paris","c":"France","i":"FR","lat":48.869,"lon":2.331,"p":9904000},{"n":"Seoul","c":"South Korea","i":"KR","lat":37.568,"lon":126.998,"p":9796000},{"n":"Jakarta","c":"Indonesia","i":"ID","lat":-6.172,"lon":106.827,"p":9125000},{"n":"London","c":"United Kingdom","i":"GB","lat":51.502,"lon":-0.119,"p":8567000},{"n":"Lima","c":"Peru","i":"PE","lat":-12.046,"lon":-77.052,"p":8012000},{"n":"Tehran","c":"Iran","i":"IR","lat":35.674,"lon":51.422,"p":7873000},{"n":"Kinshasa","c":"Congo (Kinshasa)","i":"CD","lat":-4.328,"lon":15.313,"p":7843000},{"n":"Bogota","c":"Colombia","i":"CO","lat":4.598,"lon":-74.085,"p":7772000},{"n":"Taipei","c":"Taiwan","i":"TW","lat":25.036,"lon":121.568,"p":6900273},{"n":"Bangkok","c":"Thailand","i":"TH","lat":13.752,"lon":100.515,"p":6704000},{"n":"Santiago","c":"Chile","i":"CL","lat":-33.448,"lon":-70.669,"p":5720000},{"n":"Madrid","c":"Spain","i":"ES","lat":40.402,"lon":-3.685,"p":5567000},{"n":"Singapore","c":"Singapore","i":"SG","lat":1.295,"lon":103.854,"p":5183700},{"n":"Luanda","c":"Angola","i":"AO","lat":-8.836,"lon":13.232,"p":5172900},{"n":"Baghdad","c":"Iraq","i":"IQ","lat":33.341,"lon":44.392,"p":5054000},{"n":"Khartoum","c":"Sudan","i":"SD","lat":15.59,"lon":32.532,"p":4754000},{"n":"Riyadh","c":"Saudi Arabia","i":"SA","lat":24.643,"lon":46.771,"p":4465000},{"n":"Hanoi","c":"Vietnam","i":"VN","lat":21.035,"lon":105.848,"p":4378000},{"n":"Washington, D.C.","c":"United States of America","i":"US","lat":38.901,"lon":-77.011,"p":4338000},{"n":"Rangoon","c":"Myanmar","i":"MM","lat":16.785,"lon":96.165,"p":4088000},{"n":"Abidjan","c":"Ivory Coast","i":"CI","lat":5.322,"lon":-4.042,"p":3802000},{"n":"Brasília","c":"Brazil","i":"BR","lat":-15.781,"lon":-47.918,"p":3716996},{"n":"Ankara","c":"Turkey","i":"TR","lat":39.929,"lon":32.862,"p":3716000},{"n":"Johannesburg","c":"South Africa","i":"ZA","lat":-26.168,"lon":28.028,"p":3435000},{"n":"Berlin","c":"Germany","i":"DE","lat":52.524,"lon":13.4,"p":3406000},{"n":"Algiers","c":"Algeria","i":"DZ","lat":36.765,"lon":3.049,"p":3354000},{"n":"Rome","c":"Italy","i":"IT","lat":41.898,"lon":12.481,"p":3339000},{"n":"Pyongyang","c":"North Korea","i":"KP","lat":39.021,"lon":125.753,"p":3300000},{"n":"Kabul","c":"Afghanistan","i":"AF","lat":34.519,"lon":69.181,"p":3277000},{"n":"Athens","c":"Greece","i":"GR","lat":37.985,"lon":23.731,"p":3242000},{"n":"Cape Town","c":"South Africa","i":"ZA","lat":-33.918,"lon":18.433,"p":3215000},{"n":"Addis Ababa","c":"Ethiopia","i":"ET","lat":9.035,"lon":38.698,"p":3100000},{"n":"Nairobi","c":"Kenya","i":"KE","lat":-1.281,"lon":36.815,"p":3010000},{"n":"Caracas","c":"Venezuela","i":"VE","lat":10.503,"lon":-66.919,"p":2985000},{"n":"Dar es Salaam","c":"Tanzania","i":"TZ","lat":-6.798,"lon":39.266,"p":2930000},{"n":"Lisbon","c":"Portugal","i":"PT","lat":38.725,"lon":-9.147,"p":2812000},{"n":"Kiev","c":"Ukraine","i":"UA","lat":50.435,"lon":30.515,"p":2709000},{"n":"Dakar","c":"Senegal","i":"SN","lat":14.718,"lon":-17.475,"p":2604000},{"n":"Damascus","c":"Syria","i":"SY","lat":33.502,"lon":36.298,"p":2466000},{"n":"Tunis","c":"Tunisia","i":"TN","lat":36.803,"lon":10.18,"p":2412500},{"n":"Vienna","c":"Austria","i":"AT","lat":48.202,"lon":16.365,"p":2400000},{"n":"Tripoli","c":"Libya","i":"LY","lat":32.893,"lon":13.18,"p":2189000},{"n":"Tashkent","c":"Uzbekistan","i":"UZ","lat":41.314,"lon":69.293,"p":2184000},{"n":"Havana","c":"Cuba","i":"CU","lat":23.134,"lon":-82.366,"p":2174000},{"n":"Santo Domingo","c":"Dominican Republic","i":"DO","lat":18.472,"lon":-69.902,"p":2154000},{"n":"Baku","c":"Azerbaijan","i":"AZ","lat":40.397,"lon":49.86,"p":2122300},{"n":"Accra","c":"Ghana","i":"GH","lat":5.552,"lon":-0.219,"p":2121000},{"n":"Kuwait","c":"Kuwait","i":"KW","lat":29.372,"lon":47.976,"p":2063000},{"n":"Sanaa","c":"Yemen","i":"YE","lat":15.357,"lon":44.205,"p":2008000},{"n":"Port-au-Prince","c":"Haiti","i":"HT","lat":18.543,"lon":-72.338,"p":1998000},{"n":"Bucharest","c":"Romania","i":"RO","lat":44.435,"lon":26.098,"p":1942000},{"n":"Asunción","c":"Paraguay","i":"PY","lat":-25.294,"lon":-57.643,"p":1870000},{"n":"Beirut","c":"Lebanon","i":"LB","lat":33.874,"lon":35.508,"p":1846000},{"n":"Minsk","c":"Belarus","i":"BY","lat":53.902,"lon":27.565,"p":1805000},{"n":"Brussels","c":"Belgium","i":"BE","lat":50.835,"lon":4.331,"p":1743000},{"n":"Warsaw","c":"Poland","i":"PL","lat":52.252,"lon":20.998,"p":1707000},{"n":"Rabat","c":"Morocco","i":"MA","lat":34.025,"lon":-6.836,"p":1705000},{"n":"Quito","c":"Ecuador","i":"EC","lat":-0.213,"lon":-78.502,"p":1701000},{"n":"Antananarivo","c":"Madagascar","i":"MG","lat":-18.915,"lon":47.515,"p":1697000},{"n":"Budapest","c":"Hungary","i":"HU","lat":47.502,"lon":19.081,"p":1679000},{"n":"Yaounde","c":"Cameroon","i":"CM","lat":3.869,"lon":11.515,"p":1611000},{"n":"La Paz","c":"Bolivia","i":"BO","lat":-16.496,"lon":-68.152,"p":1590000},{"n":"Abuja","c":"Nigeria","i":"NG","lat":9.085,"lon":7.531,"p":1576000},{"n":"Harare","c":"Zimbabwe","i":"ZW","lat":-17.816,"lon":31.043,"p":1572000},{"n":"Montevideo","c":"Uruguay","i":"UY","lat":-34.856,"lon":-56.173,"p":1513000},{"n":"Bamako","c":"Mali","i":"ML","lat":12.652,"lon":-8.002,"p":1494000},{"n":"Conakry","c":"Guinea","i":"GN","lat":9.533,"lon":-13.682,"p":1494000},{"n":"Phnom Penh","c":"Cambodia","i":"KH","lat":11.552,"lon":104.915,"p":1466000},{"n":"Lomé","c":"Togo","i":"TG","lat":6.134,"lon":1.221,"p":1452000},{"n":"Doha","c":"Qatar","i":"QA","lat":25.287,"lon":51.533,"p":1450000},{"n":"Kuala Lumpur","c":"Malaysia","i":"MY","lat":3.169,"lon":101.698,"p":1448000},{"n":"Maputo","c":"Mozambique","i":"MZ","lat":-25.953,"lon":32.587,"p":1446000},{"n":"San Salvador","c":"El Salvador","i":"SV","lat":13.712,"lon":-89.205,"p":1433000},{"n":"Kampala","c":"Uganda","i":"UG","lat":0.319,"lon":32.581,"p":1420000},{"n":"Brazzaville","c":"Congo (Brazzaville)","i":"CG","lat":-4.257,"lon":15.283,"p":1355000},{"n":"Pretoria","c":"South Africa","i":"ZA","lat":-25.705,"lon":28.227,"p":1338000},{"n":"Lusaka","c":"Zambia","i":"ZM","lat":-15.415,"lon":28.281,"p":1328000},{"n":"San José","c":"Costa Rica","i":"CR","lat":9.937,"lon":-84.086,"p":1284000},{"n":"Panama City","c":"Panama","i":"PA","lat":8.97,"lon":-79.535,"p":1281000},{"n":"Stockholm","c":"Sweden","i":"SE","lat":59.353,"lon":18.095,"p":1264000},{"n":"Sofia","c":"Bulgaria","i":"BG","lat":42.685,"lon":23.315,"p":1185000},{"n":"Prague","c":"Czech Republic","i":"CZ","lat":50.085,"lon":14.464,"p":1162000},{"n":"Ouagadougou","c":"Burkina Faso","i":"BF","lat":12.372,"lon":-1.527,"p":1149000},{"n":"Ottawa","c":"Canada","i":"CA","lat":45.419,"lon":-75.702,"p":1145000},{"n":"Helsinki","c":"Finland","i":"FI","lat":60.178,"lon":24.932,"p":1115000},{"n":"Yerevan","c":"Armenia","i":"AM","lat":40.183,"lon":44.512,"p":1102000},{"n":"Mogadishu","c":"Somalia","i":"SO","lat":2.069,"lon":45.365,"p":1100000},{"n":"Tbilisi","c":"Georgia","i":"GE","lat":41.727,"lon":44.789,"p":1100000},{"n":"Belgrade","c":"Serbia","i":"RS","lat":44.821,"lon":20.466,"p":1099000},{"n":"Dushanbe","c":"Tajikistan","i":"TJ","lat":38.56,"lon":68.774,"p":1086244},{"n":"København","c":"Denmark","i":"DK","lat":55.681,"lon":12.562,"p":1085000},{"n":"Amman","c":"Jordan","i":"JO","lat":31.952,"lon":35.931,"p":1060000},{"n":"Dublin","c":"Ireland","i":"IE","lat":53.335,"lon":-6.251,"p":1059000},{"n":"Monrovia","c":"Liberia","i":"LR","lat":6.315,"lon":-10.8,"p":1041000},{"n":"Amsterdam","c":"Netherlands","i":"NL","lat":52.352,"lon":4.915,"p":1031000},{"n":"Jerusalem","c":"Israel","i":"IL","lat":31.778,"lon":35.207,"p":1029300},{"n":"Guatemala","c":"Guatemala","i":"GT","lat":14.623,"lon":-90.529,"p":1024000},{"n":"Ndjamena","c":"Chad","i":"TD","lat":12.115,"lon":15.047,"p":989000},{"n":"Tegucigalpa","c":"Honduras","i":"HN","lat":14.104,"lon":-87.219,"p":946000},{"n":"Kingston","c":"Jamaica","i":"JM","lat":17.977,"lon":-76.767,"p":937700},{"n":"Naypyidaw","c":"Myanmar","i":"MM","lat":19.769,"lon":96.117,"p":930000},{"n":"Djibouti","c":"Djibouti","i":"DJ","lat":11.595,"lon":43.148,"p":923000},{"n":"Managua","c":"Nicaragua","i":"NI","lat":12.155,"lon":-86.27,"p":920000},{"n":"Niamey","c":"Niger","i":"NE","lat":13.519,"lon":2.115,"p":915000},{"n":"Tirana","c":"Albania","i":"AL","lat":41.328,"lon":19.819,"p":895350},{"n":"Kathmandu","c":"Nepal","i":"NP","lat":27.719,"lon":85.315,"p":895000},{"n":"Ulaanbaatar","c":"Mongolia","i":"MN","lat":47.919,"lon":106.915,"p":885000},{"n":"Kigali","c":"Rwanda","i":"RW","lat":-1.952,"lon":30.059,"p":860000},{"n":"Bishkek","c":"Kyrgyzstan","i":"KG","lat":42.875,"lon":74.583,"p":837000},{"n":"Oslo","c":"Norway","i":"NO","lat":59.919,"lon":10.748,"p":835000},{"n":"Bangui","c":"Central African Republic","i":"CF","lat":4.367,"lon":18.558,"p":831925},{"n":"Freetown","c":"Sierra Leone","i":"SL","lat":8.472,"lon":-13.236,"p":827000},{"n":"Islamabad","c":"Pakistan","i":"PK","lat":33.702,"lon":73.165,"p":780000},{"n":"Cotonou","c":"Benin","i":"BJ","lat":6.402,"lon":2.518,"p":762000},{"n":"Vientiane","c":"Laos","i":"LA","lat":17.967,"lon":102.6,"p":754000},{"n":"Riga","c":"Latvia","i":"LV","lat":56.95,"lon":24.1,"p":742572},{"n":"Nouakchott","c":"Mauritania","i":"MR","lat":18.086,"lon":-15.975,"p":742144},{"n":"Muscat","c":"Oman","i":"OM","lat":23.613,"lon":58.593,"p":734697},{"n":"Ashgabat","c":"Turkmenistan","i":"TM","lat":37.95,"lon":58.383,"p":727700},{"n":"Zagreb","c":"Croatia","i":"HR","lat":45.8,"lon":16.0,"p":722526},{"n":"Sarajevo","c":"Bosnia and Herzegovina","i":"BA","lat":43.85,"lon":18.383,"p":696731},{"n":"Chișinău","c":"Moldova","i":"MD","lat":47.005,"lon":28.858,"p":688134},{"n":"Lilongwe","c":"Malawi","i":"MW","lat":-13.983,"lon":33.783,"p":646750},{"n":"Asmara","c":"Eritrea","i":"ER","lat":15.333,"lon":38.933,"p":620802},{"n":"Abu Dhabi","c":"United Arab Emirates","i":"AE","lat":24.467,"lon":54.367,"p":603492},{"n":"Port Louis","c":"Mauritius","i":"MU","lat":-20.167,"lon":57.5,"p":595491},{"n":"Libreville","c":"Gabon","i":"GA","lat":0.385,"lon":9.458,"p":578156},{"n":"Manama","c":"Bahrain","i":"BH","lat":26.236,"lon":50.583,"p":563920},{"n":"Vilnius","c":"Lithuania","i":"LT","lat":54.683,"lon":25.317,"p":542366},{"n":"Skopje","c":"Macedonia","i":"MK","lat":42.0,"lon":21.433,"p":494087},{"n":"Hargeysa","c":"Somaliland","i":"-99","lat":9.56,"lon":44.065,"p":477876},{"n":"Pristina","c":"Kosovo","i":"-99","lat":42.667,"lon":21.166,"p":465186},{"n":"Bloemfontein","c":"South Africa","i":"ZA","lat":-29.12,"lon":26.23,"p":463064},{"n":"Bratislava","c":"Slovakia","i":"SK","lat":48.15,"lon":17.117,"p":423737},{"n":"Bissau","c":"Guinea Bissau","i":"GW","lat":11.865,"lon":-15.598,"p":403339},{"n":"Tallinn","c":"Estonia","i":"EE","lat":59.434,"lon":24.728,"p":394024},{"n":"Wellington","c":"New Zealand","i":"NZ","lat":-41.3,"lon":174.783,"p":393400},{"n":"Valletta","c":"Malta","i":"MT","lat":35.9,"lon":14.515,"p":368250},{"n":"Maseru","c":"Lesotho","i":"LS","lat":-29.317,"lon":27.483,"p":361324},{"n":"Astana","c":"Kazakhstan","i":"KZ","lat":51.181,"lon":71.428,"p":345604},{"n":"Bujumbura","c":"Burundi","i":"BI","lat":-3.376,"lon":29.36,"p":331700},{"n":"Canberra","c":"Australia","i":"AU","lat":-35.283,"lon":149.129,"p":327700},{"n":"New Delhi","c":"India","i":"IN","lat":28.6,"lon":77.2,"p":317797},{"n":"Ljubljana","c":"Slovenia","i":"SI","lat":46.055,"lon":14.515,"p":314807},{"n":"Bandar Seri Begawan","c":"Brunei","i":"BN","lat":4.883,"lon":114.933,"p":296500},{"n":"Port-of-Spain","c":"Trinidad and Tobago","i":"TT","lat":10.652,"lon":-61.517,"p":294934},{"n":"Port Moresby","c":"Papua New Guinea","i":"PG","lat":-9.465,"lon":147.193,"p":283733},{"n":"Bern","c":"Switzerland","i":"CH","lat":46.917,"lon":7.467,"p":275329},{"n":"Windhoek","c":"Namibia","i":"NA","lat":-22.57,"lon":17.084,"p":268132},{"n":"Georgetown","c":"Guyana","i":"GY","lat":6.802,"lon":-58.167,"p":264350},{"n":"Paramaribo","c":"Suriname","i":"SR","lat":5.835,"lon":-55.167,"p":254169},{"n":"Dili","c":"East Timor","i":"TL","lat":-8.559,"lon":125.579,"p":234331},{"n":"Nassau","c":"The Bahamas","i":"BS","lat":25.083,"lon":-77.35,"p":227940},{"n":"Sucre","c":"Bolivia","i":"BO","lat":-19.041,"lon":-65.26,"p":224838},{"n":"Nicosia","c":"Cyprus","i":"CY","lat":35.167,"lon":33.367,"p":224300},{"n":"Colombo","c":"Sri Lanka","i":"LK","lat":6.932,"lon":79.858,"p":217000},{"n":"Gaborone","c":"Botswana","i":"BW","lat":-24.646,"lon":25.912,"p":208411},{"n":"Yamoussoukro","c":"Ivory Coast","i":"CI","lat":6.818,"lon":-5.276,"p":206499},{"n":"Bridgetown","c":"Barbados","i":"BB","lat":13.102,"lon":-59.617,"p":191152},{"n":"Suva","c":"Fiji","i":"FJ","lat":-18.133,"lon":178.442,"p":175399},{"n":"Reykjavík","c":"Iceland","i":"IS","lat":64.15,"lon":-21.95,"p":166212},{"n":"Malabo","c":"Equatorial Guinea","i":"GQ","lat":3.75,"lon":8.783,"p":155963},{"n":"Podgorica","c":"Montenegro","i":"ME","lat":42.466,"lon":19.266,"p":145850},{"n":"Moroni","c":"Comoros","i":"KM","lat":-11.704,"lon":43.24,"p":128698},{"n":"Praia","c":"Cape Verde","i":"CV","lat":14.917,"lon":-23.517,"p":113364},{"n":"Malé","c":"Maldives","i":"MV","lat":4.167,"lon":73.5,"p":112927},{"n":"Juba","c":"South Sudan","i":"SS","lat":4.83,"lon":31.58,"p":111975},{"n":"Luxembourg","c":"Luxembourg","i":"LU","lat":49.612,"lon":6.13,"p":107260},{"n":"Thimphu","c":"Bhutan","i":"BT","lat":27.473,"lon":89.639,"p":98676},{"n":"Mbabane","c":"Swaziland","i":"SZ","lat":-26.317,"lon":31.133,"p":90138},{"n":"São Tomé","c":"Sao Tome and Principe","i":"ST","lat":0.333,"lon":6.733,"p":88219},{"n":"Honiara","c":"Solomon Islands","i":"SB","lat":-9.438,"lon":159.95,"p":76328},{"n":"Apia","c":"Samoa","i":"WS","lat":-13.842,"lon":-171.739,"p":61916},{"n":"Andorra","c":"Andorra","i":"AD","lat":42.5,"lon":1.516,"p":53998},{"n":"Kingstown","c":"Saint Vincent and the Grenadines","i":"VC","lat":13.148,"lon":-61.212,"p":49485},{"n":"Port Vila","c":"Vanuatu","i":"VU","lat":-17.733,"lon":168.317,"p":44040},{"n":"Banjul","c":"The Gambia","i":"GM","lat":13.454,"lon":-16.592,"p":43094},{"n":"Nukualofa","c":"Tonga","i":"TO","lat":-21.139,"lon":-175.221,"p":42620},{"n":"Castries","c":"Saint Lucia","i":"LC","lat":14.002,"lon":-61.0,"p":37963},{"n":"Monaco","c":"Monaco","i":"MC","lat":43.74,"lon":7.407,"p":36371},{"n":"Vaduz","c":"Liechtenstein","i":"LI","lat":47.134,"lon":9.517,"p":36281},{"n":"Saint John's","c":"Antigua and Barbuda","i":"AG","lat":17.118,"lon":-61.85,"p":35499},{"n":"Saint George's","c":"Grenada","i":"GD","lat":12.053,"lon":-61.742,"p":33734},{"n":"Victoria","c":"Seychelles","i":"SC","lat":-4.617,"lon":55.45,"p":33576},{"n":"San Marino","c":"San Marino","i":"SM","lat":43.936,"lon":12.442,"p":29579},{"n":"Tarawa","c":"Kiribati","i":"KI","lat":1.338,"lon":173.018,"p":28802},{"n":"Majuro","c":"Marshall Islands","i":"MH","lat":7.103,"lon":171.38,"p":25400},{"n":"Roseau","c":"Dominica","i":"DM","lat":15.301,"lon":-61.387,"p":23336},{"n":"Basseterre","c":"Saint Kitts and Nevis","i":"KN","lat":17.302,"lon":-62.717,"p":21887},{"n":"Belmopan","c":"Belize","i":"BZ","lat":17.252,"lon":-88.767,"p":15220},{"n":"Melekeok","c":"Palau","i":"PW","lat":7.487,"lon":134.627,"p":7026},{"n":"Funafuti","c":"Tuvalu","i":"TV","lat":-8.517,"lon":179.217,"p":4749},{"n":"Palikir","c":"Federated States of Micronesia","i":"FM","lat":6.917,"lon":158.15,"p":4645},{"n":"Vatican City","c":"Vatican (Holy See)","i":"VA","lat":41.903,"lon":12.453,"p":832}];

        // equirectangular projection — lat/lon → 1000x500 viewBox coords
        function _wm_project(lat, lon) {
            const latC = Math.max(-85, Math.min(85, lat));
            return {
                x: (lon + 180) / 360 * 1000,
                y: (90 - latC) / 180 * 500,
            };
        }

        let _wm_svg_cache = null;
        let _wm_svg_inflight = null;
        function _wm_loadCountriesSvg() {
            if (_wm_svg_cache) return Promise.resolve(_wm_svg_cache);
            if (_wm_svg_inflight) return _wm_svg_inflight;
            _wm_svg_inflight = fetch('/assets/world-countries.svg', { credentials: 'include' })
                .then(r => r.ok ? r.text() : Promise.reject(new Error(`HTTP ${r.status}`)))
                .then(txt => { _wm_svg_cache = txt; return txt; })
                .finally(() => { _wm_svg_inflight = null; });
            return _wm_svg_inflight;
        }

        // — main map —
        function WorldMap({ clusters, compact = false, onClusterClick }) {
            const { t } = useTranslation();
            const [svgText, setSvgText] = useState(null);
            const [err, setErr] = useState(null);
            const [hovered, setHovered] = useState(null);
            // MK May 2026 — zoom/pan state. scale=1 = full world; viewBox shrinks +
            // pans relative to centre. Both SVG layers reference this so they
            // always stay in lockstep (countries + dots + capitals all rendered
            // through the same dynamic viewBox).
            const [view, setView] = useState({ scale: 1, panX: 0, panY: 0 });
            const [showCapitals, setShowCapitals] = useState(false);
            const dragRef = useRef(null);
            const containerRef = useRef(null);

            useEffect(() => {
                let cancelled = false;
                _wm_loadCountriesSvg()
                    .then(txt => { if (!cancelled) setSvgText(txt); })
                    .catch(e => { if (!cancelled) setErr(e.message || 'load failed'); });
                return () => { cancelled = true; };
            }, []);

            const isLight = (typeof document !== 'undefined' &&
                             document.body?.getAttribute('data-corp-theme') === 'light');
            const palette = isLight ? {
                '--wm-ocean':          '#eef3f8',
                '--wm-country-fill':   '#cfd9e2',
                '--wm-country-stroke': '#a8b5c2',
                '--wm-country-hover':  '#b9c6d3',
            } : {
                '--wm-ocean':          '#0a1424',
                '--wm-country-fill':   '#22344a',
                '--wm-country-stroke': '#3a5070',
                '--wm-country-hover':  '#365373',
            };

            const plottable = (clusters || []).filter(c => c.latitude != null && c.longitude != null);

            // Compute the active viewBox from {scale, panX, panY}.
            // pan is in viewBox-coords (range roughly ±500). Clamped so the
            // user can't pan into nothingness off the right/left/top/bottom.
            const vbW = 1000 / view.scale;
            const vbH = 500 / view.scale;
            const maxPanX = (1000 - vbW) / 2;
            const maxPanY = (500 - vbH) / 2;
            const panX = Math.max(-maxPanX, Math.min(maxPanX, view.panX));
            const panY = Math.max(-maxPanY, Math.min(maxPanY, view.panY));
            const vbX = panX + (1000 - vbW) / 2;
            const vbY = panY + (500 - vbH) / 2;
            const viewBox = `${vbX} ${vbY} ${vbW} ${vbH}`;

            // Auto-show capital DOTS once user has zoomed past 1.2x;
            // labels appear only past 2.5x to avoid clutter.
            const showCapitalDots = showCapitals || view.scale >= 1.2;
            const showCapitalLabels = (showCapitals && view.scale >= 1.8) || view.scale >= 2.5;

            // dot/ring sizes shrink with zoom so they don't dominate at 8x
            // MK May 2026 — was dotR=8 (≈13px on screen at 1x) which Nico flagged
            // as too chunky against the country shapes. Halved the base footprint;
            // halo + pulse ring also slimmed down proportionally so the dot still
            // stands out without dominating.
            const sizeFactor = Math.max(0.4, 1 / Math.sqrt(view.scale));
            const dotR  = (compact ? 3.5 : 5) * sizeFactor;
            const ringR = (compact ? 7 : 11) * sizeFactor;
            const capDotR = 1.6 * sizeFactor;

            // MK May 2026 — greedy label-collision avoidance. Capitals are pre-sorted
            // by population descending; we project + viewport-clip, then walk the list
            // and place each label only if its bounding box doesn't overlap any
            // already-placed label. Smaller capitals lose their label (dot stays).
            // Without this, Brazzaville/Kinshasa, Conakry/Freetown/Monrovia, etc.
            // print on top of each other and the names mush together.
            const fontSize = 3.5 * sizeFactor;
            const labelPad = 0.6 * sizeFactor;
            const visibleCapitals = [];
            const placedLabelBoxes = [];
            if (showCapitalDots) {
                for (const c of _wm_capitals) {
                    const p = _wm_project(c.lat, c.lon);
                    // viewport-clip in viewBox coords
                    if (p.x < vbX || p.x > vbX + vbW || p.y < vbY || p.y > vbY + vbH) continue;
                    let labelOk = false;
                    if (showCapitalLabels) {
                        // estimate label bounding box: width ~ name.length * fontSize * 0.55, height ~ fontSize * 1.2
                        // text is rendered right-of-dot, offset by capDotR + 1.5
                        const lx = p.x + capDotR + 1.5;
                        const ly = p.y + 1.5 - fontSize;  // text baseline → top of box
                        const lw = c.n.length * fontSize * 0.55 + 2 * labelPad;
                        const lh = fontSize * 1.2 + 2 * labelPad;
                        // collision check vs already-placed boxes
                        let collides = false;
                        for (const b of placedLabelBoxes) {
                            if (lx < b.x + b.w && lx + lw > b.x && ly < b.y + b.h && ly + lh > b.y) {
                                collides = true;
                                break;
                            }
                        }
                        if (!collides) {
                            placedLabelBoxes.push({x: lx, y: ly, w: lw, h: lh});
                            labelOk = true;
                        }
                    }
                    visibleCapitals.push({...c, _x: p.x, _y: p.y, _labelOk: labelOk});
                }
            }

            // wheel-zoom — toward cursor for natural feel.
            // MK 2026-05-30 — React's onWheel synthetic prop registers as a PASSIVE
            // listener since React 17, so calling preventDefault() inside throws
            // the "Unable to preventDefault inside passive event listener" warning
            // we were seeing 30+ times per scroll session. Attach via raw
            // addEventListener({passive:false}) instead. The handler reads vbW/vbH/vbX/vbY
            // through a ref so we don't re-attach on every render.
            const wheelHandlerRef = useRef(null);
            wheelHandlerRef.current = (e) => {
                if (compact) return;
                e.preventDefault();
                const delta = e.deltaY < 0 ? 1.25 : 0.8;
                const rect = containerRef.current?.getBoundingClientRect();
                if (!rect) return;
                const cx = ((e.clientX - rect.left) / rect.width) * vbW + vbX;
                const cy = ((e.clientY - rect.top) / rect.height) * vbH + vbY;
                setView(v => {
                    const newScale = Math.max(1, Math.min(8, v.scale * delta));
                    if (newScale === v.scale) return v;
                    const newVbW = 1000 / newScale;
                    const newVbH = 500 / newScale;
                    const newVbX = cx - ((e.clientX - rect.left) / rect.width) * newVbW;
                    const newVbY = cy - ((e.clientY - rect.top) / rect.height) * newVbH;
                    return {
                        scale: newScale,
                        panX: newVbX - (1000 - newVbW) / 2,
                        panY: newVbY - (500 - newVbH) / 2,
                    };
                });
            };
            useEffect(() => {
                const el = containerRef.current;
                if (!el) return;
                const wheelListener = (e) => wheelHandlerRef.current && wheelHandlerRef.current(e);
                el.addEventListener('wheel', wheelListener, { passive: false });
                return () => el.removeEventListener('wheel', wheelListener);
            }, []);

            const handleMouseDown = (e) => {
                if (compact || view.scale === 1) return;
                dragRef.current = { startX: e.clientX, startY: e.clientY, panX: view.panX, panY: view.panY };
            };
            const handleMouseMove = (e) => {
                if (!dragRef.current) return;
                const rect = containerRef.current?.getBoundingClientRect();
                if (!rect) return;
                const dx = ((e.clientX - dragRef.current.startX) / rect.width) * vbW;
                const dy = ((e.clientY - dragRef.current.startY) / rect.height) * vbH;
                setView(v => ({ ...v, panX: dragRef.current.panX - dx, panY: dragRef.current.panY - dy }));
            };
            const handleMouseUp = () => { dragRef.current = null; };

            const zoomIn  = () => setView(v => ({ ...v, scale: Math.min(8, v.scale * 1.5) }));
            const zoomOut = () => setView(v => ({ ...v, scale: Math.max(1, v.scale / 1.5) }));
            const resetView = () => setView({ scale: 1, panX: 0, panY: 0 });

            return (
                <div
                    ref={containerRef}
                    className="relative w-full rounded-2xl overflow-hidden border select-none"
                    style={{
                        ...palette,
                        background: 'var(--wm-ocean)',
                        borderColor: isLight ? '#cbd5e0' : '#1a2738',
                        aspectRatio: '2 / 1',
                        maxHeight: compact ? '14rem' : '62vh',
                        cursor: view.scale > 1 ? (dragRef.current ? 'grabbing' : 'grab') : 'default',
                    }}
                    onMouseDown={handleMouseDown}
                    onMouseMove={handleMouseMove}
                    onMouseUp={handleMouseUp}
                    onMouseLeave={handleMouseUp}
                >
                    {err && (
                        <div className="absolute inset-0 flex items-center justify-center text-red-400 text-sm">
                            {t('worldMapLoadFailed') || 'Failed to load world map'}: {err}
                        </div>
                    )}
                    {!err && !svgText && (
                        <div className="absolute inset-0 flex items-center justify-center text-sm"
                             style={{color: isLight ? '#6b7280' : '#94a3b8'}}>
                            {t('worldMapLoading') || 'Loading map…'}
                        </div>
                    )}
                    {svgText && (
                        <>
                            {/* countries layer — same dynamic viewBox as the overlay */}
                            <div
                                className="absolute inset-0 w-full h-full pointer-events-none"
                                dangerouslySetInnerHTML={{
                                    __html: svgText
                                        .replace(/viewBox="[^"]*"/, `viewBox="${viewBox}"`)
                                        .replace('<svg ', '<svg style="position:absolute;inset:0;width:100%;height:100%;display:block" '),
                                }}
                            />

                            {/* dots + capitals overlay */}
                            <svg viewBox={viewBox} preserveAspectRatio="xMidYMid meet"
                                 className="absolute inset-0 w-full h-full pointer-events-none">
                                {/* capitals first (so cluster dots sit on top).
                                    _x/_y are pre-projected, _labelOk reflects greedy collision-test result */}
                                {visibleCapitals.map((cap, i) => (
                                    <g key={`cap-${i}`}>
                                        <circle cx={cap._x} cy={cap._y} r={capDotR}
                                                fill={isLight ? '#475569' : '#94a3b8'}
                                                opacity="0.85" />
                                        {cap._labelOk && (
                                            <text x={cap._x + capDotR + 1.5} y={cap._y + 1.5}
                                                  fontSize={fontSize}
                                                  fill={isLight ? '#1e293b' : '#cbd5e1'}
                                                  style={{paintOrder: 'stroke', stroke: isLight ? '#ffffff' : '#0a1424', strokeWidth: 0.4 * sizeFactor}}>
                                                {cap.n}
                                            </text>
                                        )}
                                    </g>
                                ))}
                                {/* cluster dots */}
                                {plottable.map(c => {
                                    const { x, y } = _wm_project(c.latitude, c.longitude);
                                    const color = c.connected
                                        ? '#22c55e'
                                        : (c.status === 'running' ? '#f59e0b' : '#ef4444');
                                    return (
                                        <g key={c.id}
                                           className="pointer-events-auto"
                                           style={{ cursor: onClusterClick ? 'pointer' : 'default' }}
                                           onMouseEnter={() => setHovered({ cluster: c, x, y })}
                                           onMouseLeave={() => setHovered(null)}
                                           onClick={() => onClusterClick && onClusterClick(c)}>
                                            <circle cx={x} cy={y} r={ringR} fill={color} opacity="0">
                                                <animate attributeName="r" from={ringR * 0.6} to={ringR * 2.2} dur="2.6s" repeatCount="indefinite" />
                                                <animate attributeName="opacity" from="0.45" to="0" dur="2.6s" repeatCount="indefinite" />
                                            </circle>
                                            <circle cx={x} cy={y} r={dotR + 1.5*sizeFactor} fill={isLight ? '#fff' : '#0a1424'} opacity="0.85" />
                                            <circle cx={x} cy={y} r={dotR} fill={color}
                                                    stroke={isLight ? '#0a1424' : '#fff'} strokeWidth={1.2 * sizeFactor} />
                                        </g>
                                    );
                                })}
                            </svg>

                            {/* tooltip */}
                            {hovered && (() => {
                                // project tooltip position via active viewBox
                                const xPct = ((hovered.x - vbX) / vbW) * 100;
                                const yPct = ((hovered.y - vbY) / vbH) * 100;
                                return (
                                    <div
                                        className="absolute pointer-events-none rounded-xl border shadow-2xl px-3 py-2 text-sm z-10 min-w-[12rem]"
                                        style={{
                                            background: isLight ? '#ffffff' : '#0f172aee',
                                            borderColor: isLight ? '#cbd5e0' : '#334155',
                                            color: isLight ? '#0f172a' : '#f1f5f9',
                                            left: `calc(${xPct}% + 14px)`,
                                            top: `calc(${yPct}% + 14px)`,
                                        }}
                                    >
                                        <div className="font-semibold">{hovered.cluster.display_name || hovered.cluster.name}</div>
                                        {hovered.cluster.location_label && (
                                            <div className="text-xs opacity-70 mt-0.5">{hovered.cluster.location_label}</div>
                                        )}
                                        <div className="text-xs opacity-60 mt-1 font-mono">
                                            {hovered.cluster.latitude.toFixed(3)}, {hovered.cluster.longitude.toFixed(3)}
                                        </div>
                                        <div className="text-xs mt-1.5 flex items-center gap-1.5">
                                            <span style={{
                                                display: 'inline-block', width: 8, height: 8, borderRadius: 999,
                                                background: hovered.cluster.connected ? '#22c55e' : '#ef4444',
                                            }} />
                                            <span style={{color: hovered.cluster.connected ? '#22c55e' : '#ef4444'}}>
                                                {hovered.cluster.connected
                                                    ? (t('statusConnected') || 'connected')
                                                    : (t('statusDisconnected') || 'disconnected')}
                                            </span>
                                        </div>
                                    </div>
                                );
                            })()}

                            {/* control buttons — top-right */}
                            {!compact && (
                                <div className="absolute top-3 right-3 flex flex-col gap-1.5 z-20">
                                    <button onClick={zoomIn} title={t('zoomIn') || 'Zoom in'}
                                            className="w-8 h-8 rounded-md flex items-center justify-center shadow-md font-bold text-lg leading-none"
                                            style={{background: isLight ? '#ffffffd0' : '#0f172ad0', color: isLight ? '#0f172a' : '#f1f5f9', backdropFilter: 'blur(4px)'}}>+</button>
                                    <button onClick={zoomOut} title={t('zoomOut') || 'Zoom out'} disabled={view.scale === 1}
                                            className="w-8 h-8 rounded-md flex items-center justify-center shadow-md font-bold text-lg leading-none disabled:opacity-40"
                                            style={{background: isLight ? '#ffffffd0' : '#0f172ad0', color: isLight ? '#0f172a' : '#f1f5f9', backdropFilter: 'blur(4px)'}}>−</button>
                                    <button onClick={resetView} title={t('resetZoom') || 'Reset zoom'} disabled={view.scale === 1 && view.panX === 0 && view.panY === 0}
                                            className="w-8 h-8 rounded-md flex items-center justify-center shadow-md text-xs disabled:opacity-40"
                                            style={{background: isLight ? '#ffffffd0' : '#0f172ad0', color: isLight ? '#0f172a' : '#f1f5f9', backdropFilter: 'blur(4px)'}}>⟲</button>
                                    <button onClick={() => setShowCapitals(s => !s)}
                                            title={showCapitals ? (t('hideCapitals') || 'Hide capitals') : (t('showCapitals') || 'Show capitals')}
                                            className="w-8 h-8 rounded-md flex items-center justify-center shadow-md text-xs"
                                            style={{
                                                background: showCapitals
                                                    ? (isLight ? '#0072a3d0' : '#1d4ed8d0')
                                                    : (isLight ? '#ffffffd0' : '#0f172ad0'),
                                                color: showCapitals ? '#ffffff' : (isLight ? '#0f172a' : '#f1f5f9'),
                                                backdropFilter: 'blur(4px)',
                                            }}>★</button>
                                </div>
                            )}

                            {/* bottom-left badge — cluster count + zoom level */}
                            {!compact && (
                                <div
                                    className="absolute bottom-3 left-3 px-3 py-1.5 rounded-lg text-xs font-medium shadow-md pointer-events-none"
                                    style={{
                                        background: isLight ? '#ffffffd0' : '#0f172ad0',
                                        color: isLight ? '#0f172a' : '#f1f5f9',
                                        backdropFilter: 'blur(4px)',
                                    }}
                                >
                                    {plottable.length} / {(clusters || []).length} {t('plottedOfTotal') || 'plotted'}
                                    {view.scale !== 1 && <span className="opacity-60 ml-2">· {view.scale.toFixed(1)}×</span>}
                                </div>
                            )}

                            {!compact && plottable.length === 0 && view.scale === 1 && (
                                <div className="absolute inset-0 flex items-center justify-center px-4 pointer-events-none">
                                    <div
                                        className="rounded-xl border px-6 py-5 text-center max-w-md shadow-xl"
                                        style={{
                                            background: isLight ? '#ffffff' : '#0f172aee',
                                            borderColor: isLight ? '#cbd5e0' : '#334155',
                                            color: isLight ? '#0f172a' : '#f1f5f9',
                                        }}
                                    >
                                        <div className="font-semibold mb-1">{t('worldMapNoneSet') || 'No clusters plotted yet.'}</div>
                                        <div className="text-xs opacity-70">{t('worldMapSetHint') || 'Set latitude/longitude for a cluster (right pane) to place it on the map.'}</div>
                                    </div>
                                </div>
                            )}
                        </>
                    )}
                </div>
            );
        }

        // — inline location editor —
        function ClusterLocationEditor({ cluster, onSaved, onCancel }) {
            const { t } = useTranslation();
            const { getAuthHeaders } = useAuth();
            const [lat, setLat] = useState(cluster.latitude != null ? String(cluster.latitude) : '');
            const [lon, setLon] = useState(cluster.longitude != null ? String(cluster.longitude) : '');
            const [label, setLabel] = useState(cluster.location_label || '');
            const [busy, setBusy] = useState(false);
            const [err, setErr] = useState('');

            const save = async (clearMode = false) => {
                setErr(''); setBusy(true);
                try {
                    let body;
                    if (clearMode) {
                        body = { latitude: null, longitude: null, location_label: '' };
                    } else {
                        const lf = parseFloat(lat);
                        const lo = parseFloat(lon);
                        if (Number.isNaN(lf) || Number.isNaN(lo)) {
                            setErr(t('latitude') + ' / ' + t('longitude') + ': numeric required');
                            setBusy(false); return;
                        }
                        if (lf < -90 || lf > 90)   { setErr('Latitude -90..90');  setBusy(false); return; }
                        if (lo < -180 || lo > 180) { setErr('Longitude -180..180'); setBusy(false); return; }
                        body = { latitude: lf, longitude: lo, location_label: label };
                    }
                    const r = await fetch(`${API_URL}/clusters/${cluster.id}/location`, {
                        method: 'PUT',
                        credentials: 'include',
                        headers: { 'Content-Type': 'application/json', ...getAuthHeaders() },
                        body: JSON.stringify(body),
                    });
                    const data = await r.json().catch(() => ({}));
                    if (!r.ok) { setErr(data.error || `HTTP ${r.status}`); setBusy(false); return; }
                    onSaved && onSaved(data);
                } catch {
                    setErr('Network error');
                } finally { setBusy(false); }
            };

            return (
                <div className="space-y-3">
                    <div className="grid grid-cols-2 gap-2">
                        <div>
                            <label className="block text-[11px] uppercase tracking-wide text-gray-400 mb-1">
                                {t('latitude') || 'Latitude'}
                            </label>
                            <input
                                type="text" value={lat} onChange={(e) => setLat(e.target.value)}
                                className="w-full px-2.5 py-1.5 bg-proxmox-dark border border-proxmox-border rounded-md text-white text-sm font-mono focus:outline-none focus:border-proxmox-orange"
                                placeholder="50.1109"
                            />
                        </div>
                        <div>
                            <label className="block text-[11px] uppercase tracking-wide text-gray-400 mb-1">
                                {t('longitude') || 'Longitude'}
                            </label>
                            <input
                                type="text" value={lon} onChange={(e) => setLon(e.target.value)}
                                className="w-full px-2.5 py-1.5 bg-proxmox-dark border border-proxmox-border rounded-md text-white text-sm font-mono focus:outline-none focus:border-proxmox-orange"
                                placeholder="8.6821"
                            />
                        </div>
                    </div>
                    <div>
                        <label className="block text-[11px] uppercase tracking-wide text-gray-400 mb-1">
                            {t('locationLabelField') || 'Label'} <span className="opacity-60 normal-case tracking-normal">({t('locationLabelOptional') || 'optional'})</span>
                        </label>
                        <input
                            type="text" value={label} onChange={(e) => setLabel(e.target.value.slice(0, 120))}
                            className="w-full px-2.5 py-1.5 bg-proxmox-dark border border-proxmox-border rounded-md text-white text-sm focus:outline-none focus:border-proxmox-orange"
                            placeholder="Frankfurt DC1"
                        />
                    </div>
                    {err && <div className="text-xs text-red-400">{err}</div>}
                    <div className="flex gap-2">
                        <button
                            disabled={busy}
                            onClick={() => save(false)}
                            className="flex-1 px-3 py-1.5 bg-proxmox-orange hover:bg-orange-600 disabled:opacity-50 rounded-md text-white text-sm font-medium">
                            {busy ? (t('savingLocation') || 'Saving…') : (t('saveLocation') || 'Save')}
                        </button>
                        {(cluster.latitude != null || cluster.longitude != null) && (
                            <button
                                disabled={busy}
                                onClick={() => save(true)}
                                title={t('clearLocation') || 'Clear'}
                                className="px-3 py-1.5 bg-proxmox-card hover:bg-proxmox-hover border border-proxmox-border disabled:opacity-50 rounded-md text-gray-300 hover:text-white text-sm">
                                {t('clearLocation') || 'Clear'}
                            </button>
                        )}
                    </div>
                </div>
            );
        }

        // — fullscreen route container —
        // Map dominates, narrow sidebar with cluster list + inline editor.
        function WorldMapView({ clusters, onSelectCluster, fetchClusters }) {
            const { t } = useTranslation();
            const [editing, setEditing] = useState(null);

            const plottedCount = (clusters || []).filter(c => c.latitude != null && c.longitude != null).length;

            return (
                <div className="flex flex-col xl:flex-row gap-4 p-4">
                    {/* MAP — dominates the view */}
                    <div className="flex-1 min-w-0" style={{minHeight: '36rem'}}>
                        <WorldMap clusters={clusters} onClusterClick={(c) => onSelectCluster && onSelectCluster(c)} />
                    </div>

                    {/* SIDEBAR — cluster list with inline editor */}
                    <div className="w-full xl:w-80 flex-shrink-0">
                        <div className="bg-proxmox-card border border-proxmox-border rounded-2xl overflow-hidden">
                            <div className="px-4 py-3 border-b border-proxmox-border flex items-center justify-between bg-proxmox-dark/40">
                                <div>
                                    <h3 className="text-white font-semibold text-sm">{t('clusterLocations') || 'Cluster locations'}</h3>
                                    <p className="text-xs text-gray-500">
                                        {plottedCount} / {(clusters || []).length} {t('plottedOfTotal') || 'plotted'}
                                    </p>
                                </div>
                                <Icons.Globe />
                            </div>
                            <div className="max-h-[40rem] overflow-y-auto">
                                {(clusters || []).length === 0 && (
                                    <p className="text-sm text-gray-500 px-4 py-6 text-center">
                                        {t('noClustersConfigured') || 'No clusters configured.'}
                                    </p>
                                )}
                                {(clusters || []).map(c => {
                                    const placed = c.latitude != null && c.longitude != null;
                                    const isEditing = editing && editing.id === c.id;
                                    return (
                                        <div key={c.id} className={`px-4 py-3 border-b border-proxmox-border last:border-b-0 ${isEditing ? 'bg-proxmox-dark/40' : ''}`}>
                                            <div className="flex items-center justify-between gap-2">
                                                <div className="flex-1 min-w-0">
                                                    <div className="flex items-center gap-2">
                                                        <span style={{
                                                            display: 'inline-block', width: 8, height: 8, borderRadius: 999,
                                                            background: !placed ? '#52525b' : (c.connected ? '#22c55e' : '#ef4444'),
                                                            flexShrink: 0,
                                                        }} />
                                                        <span className="text-sm font-medium text-white truncate">{c.display_name || c.name}</span>
                                                    </div>
                                                    <div className="text-xs text-gray-500 mt-0.5 ml-4 truncate">
                                                        {placed
                                                            ? (c.location_label || `${c.latitude.toFixed(2)}°, ${c.longitude.toFixed(2)}°`)
                                                            : (t('locationNotSet') || 'Location not set')}
                                                    </div>
                                                </div>
                                                <button
                                                    onClick={() => setEditing(isEditing ? null : c)}
                                                    className="text-xs px-2.5 py-1 rounded-md bg-proxmox-dark hover:bg-proxmox-hover text-gray-300 hover:text-white border border-proxmox-border whitespace-nowrap">
                                                    {isEditing
                                                        ? (t('close') || 'Close')
                                                        : (placed ? (t('editLocation') || 'Edit') : (t('setLocation') || 'Set'))}
                                                </button>
                                            </div>
                                            {isEditing && (
                                                <div className="mt-3 pt-3 border-t border-proxmox-border/50">
                                                    <ClusterLocationEditor
                                                        cluster={c}
                                                        onSaved={() => { setEditing(null); fetchClusters && fetchClusters(); }}
                                                        onCancel={() => setEditing(null)}
                                                    />
                                                </div>
                                            )}
                                        </div>
                                    );
                                })}
                            </div>
                        </div>
                    </div>
                </div>
            );
        }

/**
 * AEGIS-AI: Autonomous 3D Cyber Threat Surface & Ingress Connectivity Globe
 * 
 * Visual Architecture:
 * - High-density continental landmass dot-matrix representing Earth's continents.
 * - Global Threat Intelligence Telemetry Mesh connecting regional ingress sensor gateways
 *   (US-East, US-West, EU-Central, UK, APAC, Oceania, South America).
 * - Dynamic 3D Quadratic Bezier curved connectivity arcs with traveling photon energy pulses.
 * - Multi-layered atmospheric corona glow and dual orbital HUD compass rings.
 * - Active radar sonar sweep scanning across perimeter vectors.
 * - 100% Feature Parity between Three.js WebGL and HTML5 High-DPI Canvas 2D engine.
 * - Full interactive drag-to-orbit controls (mouse & touch) and node hover inspection.
 */

window.AegisGlobe = (function () {
    'use strict';

    // =========================================================================
    // 1. Continental Landmass & Regional Sensor Gateway Datasets
    // =========================================================================
    const CONTINENT_BOXES = [
        // North America
        [15, 30, -115, -80], [30, 50, -125, -70], [50, 68, -145, -55], [60, 72, -168, -135],
        // Central America & Caribbean
        [8, 22, -90, -75],
        // South America
        [-55, -20, -75, -55], [-20, 12, -80, -35], [-10, 5, -55, -35],
        // Europe
        [36, 60, -10, 30], [55, 71, 5, 45], [45, 58, 20, 40],
        // Africa
        [-35, 0, 12, 35], [0, 37, -18, 52], [-10, 15, -15, 10], [-25, -10, 43, 50],
        // Middle East
        [15, 35, 35, 60],
        // Asia
        [10, 35, 65, 95], [20, 55, 95, 140], [45, 75, 40, 145], [55, 75, 145, 175],
        // India & Sri Lanka
        [6, 32, 68, 88],
        // Japan & Korea
        [31, 45, 126, 145],
        // Southeast Asia & Indonesia
        [-10, 15, 95, 140],
        // Australia
        [-40, -12, 112, 154],
        // UK & Ireland
        [50, 59, -10, 2],
        // New Zealand
        [-47, -34, 166, 178],
        // Iceland & Greenland
        [63, 67, -25, -13], [60, 83, -55, -20]
    ];

    // Pre-calculate ~1,200 continental surface coordinates (lat, lon)
    const CONTINENT_POINTS = [];
    (function generateLandPoints() {
        for (let i = 0; i < CONTINENT_BOXES.length; i++) {
            const b = CONTINENT_BOXES[i];
            let lat = b[0];
            while (lat <= b[1]) {
                let lon = b[2];
                const cosLat = Math.max(0.2, Math.cos(lat * Math.PI / 180));
                const stepLon = Math.min(8.0, 4.2 / cosLat);
                while (lon <= b[3]) {
                    CONTINENT_POINTS.push({ lat: lat, lon: lon });
                    lon += stepLon;
                }
                lat += 3.8;
            }
        }
    })();

    const REGIONAL_GATEWAYS = [
        { id: 'us-east', name: 'US-East Relay', location: 'Ashburn, VA', role: 'Telemetry Stream', lat: 39.04, lon: -77.48, color: '#00f0ff' },
        { id: 'us-west', name: 'US-West Sentinel', location: 'Silicon Valley, CA', role: 'WAF & Ingress Relay', lat: 37.42, lon: -122.08, color: '#38bdf8' },
        { id: 'eu-central', name: 'EU-Central PoP', location: 'Frankfurt, Germany', role: 'TLS / Cert Monitor', lat: 50.11, lon: 8.68, color: '#10b981' },
        { id: 'uk-south', name: 'UK Cloud Hub', location: 'London, UK', role: 'DNS Authority Sensor', lat: 51.51, lon: -0.13, color: '#38bdf8' },
        { id: 'apac', name: 'APAC Edge Node', location: 'Tokyo, Japan', role: 'Multi-Region Ingress', lat: 35.68, lon: 139.69, color: '#f59e0b' },
        { id: 'oceania', name: 'Oceania Sensor', location: 'Sydney, Australia', role: 'Perimeter Transit', lat: -33.87, lon: 151.21, color: '#38bdf8' },
        { id: 'sa-east', name: 'SA Transit Relay', location: 'São Paulo, Brazil', role: 'Regional Gateway', lat: -23.55, lon: -46.63, color: '#a855f7' }
    ];

    // Standby mesh arcs connecting regional gateways
    const STANDBY_ARCS = [
        ['us-east', 'eu-central'],
        ['us-west', 'apac'],
        ['eu-central', 'uk-south'],
        ['apac', 'oceania'],
        ['us-east', 'sa-east']
    ];

    // Shared state
    let isSpinning = true;
    let prefersReducedMotion = false;
    let currentTargetPin = null; // { name, lat, lon, city, country, asn }
    let globalActiveMode = 'webgl'; // 'webgl' or 'canvas2d'
    let animationId = null;

    // Three.js instances
    let scene, camera, renderer, globeGroup;
    let threeNodes = [];
    let threePulseRings = [];
    let threeArcs = [];
    let threeBeads = [];
    let threeRadarSweep = null;
    let tooltipEl = null;

    // =========================================================================
    // 2. High-Fidelity Canvas 2D Cyber Globe Engine (Robust Fallback)
    // =========================================================================
    function runCanvas2DGlobe(container, width, height) {
        if (!container) return;
        globalActiveMode = 'canvas2d';
        container.innerHTML = '';

        const dpr = window.devicePixelRatio || 1;
        const canvas = document.createElement('canvas');
        canvas.id = 'globe-canvas';
        canvas.width = width * dpr;
        canvas.height = height * dpr;
        canvas.style.cssText = 'position:absolute;top:0;left:0;width:100%;height:100%;display:block;cursor:grab;';
        container.appendChild(canvas);

        const ctx = canvas.getContext('2d');
        if (!ctx) return;
        ctx.scale(dpr, dpr);

        let rotY = 0.0;
        let rotX = 0.22; // slight Earth axial tilt (~12.6 degrees)
        let isDragging = false;
        let prevMouse = { x: 0, y: 0 };
        let radarAngle = 0;
        let pulsePhase = 0;

        // Mouse & Touch Drag Controls
        canvas.addEventListener('mousedown', (e) => {
            isDragging = true;
            canvas.style.cursor = 'grabbing';
            prevMouse = { x: e.clientX, y: e.clientY };
        });
        window.addEventListener('mouseup', () => {
            isDragging = false;
            canvas.style.cursor = 'grab';
        });
        canvas.addEventListener('mousemove', (e) => {
            if (isDragging) {
                const dx = e.clientX - prevMouse.x;
                const dy = e.clientY - prevMouse.y;
                rotY += dx * 0.007;
                rotX = Math.max(-0.6, Math.min(0.6, rotX + dy * 0.007));
                prevMouse = { x: e.clientX, y: e.clientY };
            }
        });

        // Touch support
        canvas.addEventListener('touchstart', (e) => {
            if (e.touches.length === 1) {
                isDragging = true;
                prevMouse = { x: e.touches[0].clientX, y: e.touches[0].clientY };
            }
        }, { passive: true });
        window.addEventListener('touchend', () => { isDragging = false; });
        canvas.addEventListener('touchmove', (e) => {
            if (isDragging && e.touches.length === 1) {
                const dx = e.touches[0].clientX - prevMouse.x;
                const dy = e.touches[0].clientY - prevMouse.y;
                rotY += dx * 0.007;
                rotX = Math.max(-0.6, Math.min(0.6, rotX + dy * 0.007));
                prevMouse = { x: e.touches[0].clientX, y: e.touches[0].clientY };
            }
        }, { passive: true });

        // 3D Spherical to 2D Orthographic Projection helper
        function project(lat, lon, radius) {
            const phi = lat * Math.PI / 180;
            const theta = lon * Math.PI / 180;

            const x0 = radius * Math.cos(phi) * Math.sin(theta);
            const y0 = -radius * Math.sin(phi);
            const z0 = radius * Math.cos(phi) * Math.cos(theta);

            // Rotate around Y
            const cosY = Math.cos(rotY);
            const sinY = Math.sin(rotY);
            const x1 = x0 * cosY - z0 * sinY;
            const z1 = x0 * sinY + z0 * cosY;

            // Rotate around X
            const cosX = Math.cos(rotX);
            const sinX = Math.sin(rotX);
            const y2 = y0 * cosX - z1 * sinX;
            const z2 = y0 * sinX + z1 * cosX;

            return { x: x1, y: y2, z: z2 };
        }

        function drawFrame() {
            if (!container.parentElement) return;
            animationId = requestAnimationFrame(drawFrame);

            const curW = container.clientWidth || width;
            const curH = container.clientHeight || height;
            if (canvas.width !== curW * dpr || canvas.height !== curH * dpr) {
                canvas.width = curW * dpr;
                canvas.height = curH * dpr;
                ctx.scale(dpr, dpr);
            }

            ctx.clearRect(0, 0, curW, curH);

            const cx = curW / 2;
            const cy = curH / 2;
            const radius = Math.min(curW, curH) * 0.38;

            if (isSpinning && !prefersReducedMotion && !isDragging) {
                rotY += 0.0035;
            }
            radarAngle += 0.025;
            pulsePhase += 0.04;

            ctx.save();

            // 1. Outer Deep Atmospheric Corona Glow
            const coronaGrad = ctx.createRadialGradient(cx, cy, radius * 0.85, cx, cy, radius * 1.25);
            coronaGrad.addColorStop(0, 'rgba(0, 240, 255, 0.22)');
            coronaGrad.addColorStop(0.5, 'rgba(56, 189, 248, 0.08)');
            coronaGrad.addColorStop(1, 'rgba(0, 0, 0, 0)');
            ctx.fillStyle = coronaGrad;
            ctx.beginPath();
            ctx.arc(cx, cy, radius * 1.25, 0, Math.PI * 2);
            ctx.fill();

            // 2. Cosmic Dark Core Sphere
            const coreGrad = ctx.createRadialGradient(cx - radius * 0.25, cy - radius * 0.25, radius * 0.1, cx, cy, radius);
            coreGrad.addColorStop(0, '#0c1a32');
            coreGrad.addColorStop(0.65, '#060d1d');
            coreGrad.addColorStop(1, '#020610');
            ctx.fillStyle = coreGrad;
            ctx.beginPath();
            ctx.arc(cx, cy, radius, 0, Math.PI * 2);
            ctx.fill();

            // Sphere Rim Outline
            ctx.strokeStyle = 'rgba(0, 240, 255, 0.55)';
            ctx.lineWidth = 1.5;
            ctx.stroke();

            // 3. Cyber Wireframe Latitude & Longitude Grids (subtle holographic baseline)
            ctx.strokeStyle = 'rgba(0, 240, 255, 0.12)';
            ctx.lineWidth = 1;
            for (let i = 0; i < 6; i++) {
                const a = rotY + (i * Math.PI / 6);
                const xOff = Math.sin(a) * radius;
                ctx.beginPath();
                ctx.ellipse(cx, cy, Math.max(0.5, Math.abs(xOff)), radius, 0, 0, Math.PI * 2);
                ctx.stroke();
            }
            for (let j = 1; j <= 2; j++) {
                const yOff = (j / 3) * radius;
                const rAtY = Math.sqrt(Math.max(1, radius * radius - yOff * yOff));
                ctx.beginPath();
                ctx.ellipse(cx, cy - yOff, rAtY, yOff * 0.25, 0, 0, Math.PI * 2);
                ctx.ellipse(cx, cy + yOff, rAtY, yOff * 0.25, 0, 0, Math.PI * 2);
                ctx.stroke();
            }

            // 4. Rotating Continental Landmass Dot Matrix
            for (let i = 0; i < CONTINENT_POINTS.length; i++) {
                const pt = CONTINENT_POINTS[i];
                const p = project(pt.lat, pt.lon, radius);
                if (p.z > 0) {
                    const depth = p.z / radius; // 0 to 1
                    const alpha = 0.2 + depth * 0.75;
                    const size = 1.2 + depth * 1.2;

                    ctx.fillStyle = `rgba(0, 240, 255, ${alpha.toFixed(2)})`;
                    ctx.beginPath();
                    ctx.arc(cx + p.x, cy + p.y, size, 0, Math.PI * 2);
                    ctx.fill();
                }
            }

            // 5. Sweeping Radar Beam (Sector Sweep)
            ctx.save();
            ctx.beginPath();
            ctx.arc(cx, cy, radius, 0, Math.PI * 2);
            ctx.clip(); // Constrain within sphere boundary

            const sweepX = cx + Math.cos(radarAngle) * radius;
            const sweepY = cy + Math.sin(radarAngle) * radius;
            const radarGrad = ctx.createLinearGradient(cx, cy, sweepX, sweepY);
            radarGrad.addColorStop(0, 'rgba(0, 240, 255, 0.0)');
            radarGrad.addColorStop(1, 'rgba(0, 240, 255, 0.25)');
            ctx.strokeStyle = radarGrad;
            ctx.lineWidth = 2.5;
            ctx.beginPath();
            ctx.moveTo(cx, cy);
            ctx.lineTo(sweepX, sweepY);
            ctx.stroke();
            ctx.restore();

            // 6. Connective Cyber Telemetry Arcs & Photon Pulses
            const activeNodes = [...REGIONAL_GATEWAYS];
            let targetNode = null;
            if (currentTargetPin && currentTargetPin.lat !== null && currentTargetPin.lon !== null) {
                targetNode = {
                    id: 'target-primary',
                    name: currentTargetPin.name,
                    location: `${currentTargetPin.city || 'Edge'}, ${currentTargetPin.country || 'Global'}`,
                    role: 'Primary Ingress Gateway · Target',
                    lat: currentTargetPin.lat,
                    lon: currentTargetPin.lon,
                    isTarget: true,
                    color: '#00f0ff'
                };
            }

            // Determine arcs to draw: target arcs if target active, else standby mesh
            const arcsToDraw = [];
            if (targetNode) {
                activeNodes.forEach(rn => {
                    arcsToDraw.push({ from: rn, to: targetNode, isTarget: true });
                });
            } else {
                STANDBY_ARCS.forEach(pair => {
                    const fromNode = activeNodes.find(n => n.id === pair[0]);
                    const toNode = activeNodes.find(n => n.id === pair[1]);
                    if (fromNode && toNode) {
                        arcsToDraw.push({ from: fromNode, to: toNode, isTarget: false });
                    }
                });
            }

            // Draw curved arcs
            arcsToDraw.forEach((arc, idx) => {
                const p1 = project(arc.from.lat, arc.from.lon, radius);
                const p2 = project(arc.to.lat, arc.to.lon, radius);

                // Only draw if at least one point is on front hemisphere
                if (p1.z > -15 || p2.z > -15) {
                    const screenP1 = { x: cx + p1.x, y: cy + p1.y };
                    const screenP2 = { x: cx + p2.x, y: cy + p2.y };

                    // Elevate midpoint above sphere to form 3D curve
                    const midLat = (arc.from.lat + arc.to.lat) / 2;
                    const midLon = (arc.from.lon + arc.to.lon) / 2;
                    const dist3D = Math.sqrt(Math.pow(p1.x - p2.x, 2) + Math.pow(p1.y - p2.y, 2) + Math.pow(p1.z - p2.z, 2));
                    const midElevation = radius + Math.min(dist3D * 0.45, radius * 0.4);
                    const pMid = project(midLat, midLon, midElevation);
                    const screenMid = { x: cx + pMid.x, y: cy + pMid.y };

                    // Arc Stroke
                    const arcAlpha = Math.max(0.2, (p1.z + p2.z) / (2 * radius) * 0.85);
                    ctx.strokeStyle = arc.isTarget ? `rgba(0, 240, 255, ${arcAlpha.toFixed(2)})` : `rgba(56, 189, 248, ${(arcAlpha * 0.7).toFixed(2)})`;
                    ctx.lineWidth = arc.isTarget ? 2.0 : 1.2;
                    ctx.beginPath();
                    ctx.moveTo(screenP1.x, screenP1.y);
                    ctx.quadraticCurveTo(screenMid.x, screenMid.y, screenP2.x, screenP2.y);
                    ctx.stroke();

                    // Photon Energy Pulse Bead traveling along quadratic bezier
                    const beadProgress = ((Date.now() * 0.001 * (0.4 + (idx % 3) * 0.15)) + (idx * 0.22)) % 1;
                    const t = beadProgress;
                    const beadX = (1 - t) * (1 - t) * screenP1.x + 2 * (1 - t) * t * screenMid.x + t * t * screenP2.x;
                    const beadY = (1 - t) * (1 - t) * screenP1.y + 2 * (1 - t) * t * screenMid.y + t * t * screenP2.y;

                    ctx.fillStyle = '#ffffff';
                    ctx.shadowColor = '#00f0ff';
                    ctx.shadowBlur = 10;
                    ctx.beginPath();
                    ctx.arc(beadX, beadY, arc.isTarget ? 2.8 : 2.0, 0, Math.PI * 2);
                    ctx.fill();
                    ctx.shadowBlur = 0;
                }
            });

            // 7. Draw Regional Gateway Nodes
            activeNodes.forEach(node => {
                const p = project(node.lat, node.lon, radius);
                if (p.z > 0) {
                    const depth = p.z / radius;
                    const nx = cx + p.x;
                    const ny = cy + p.y;

                    // Sensor Node Core
                    ctx.fillStyle = node.color || '#38bdf8';
                    ctx.shadowColor = node.color || '#38bdf8';
                    ctx.shadowBlur = 8;
                    ctx.beginPath();
                    ctx.arc(nx, ny, 3.2 * depth + 1.2, 0, Math.PI * 2);
                    ctx.fill();
                    ctx.shadowBlur = 0;

                    // Pulsing beacon ring
                    const ringR = (4.0 + Math.sin(pulsePhase + node.lat) * 3.0) * depth;
                    ctx.strokeStyle = `rgba(56, 189, 248, ${(0.8 * depth).toFixed(2)})`;
                    ctx.lineWidth = 1.2;
                    ctx.beginPath();
                    ctx.arc(nx, ny, Math.max(2, ringR), 0, Math.PI * 2);
                    ctx.stroke();
                }
            });

            // 8. Draw Target Gateway Node with Radiating Radar Beacon
            if (targetNode) {
                const p = project(targetNode.lat, targetNode.lon, radius);
                if (p.z > 0) {
                    const depth = p.z / radius;
                    const tx = cx + p.x;
                    const ty = cy + p.y;

                    // Radiating Radar Rings
                    for (let rIdx = 0; rIdx < 2; rIdx++) {
                        const rSize = (6.0 + ((pulsePhase * 8 + rIdx * 10) % 24)) * depth;
                        const rAlpha = Math.max(0, 1 - rSize / (24 * depth));
                        ctx.strokeStyle = `rgba(0, 240, 255, ${rAlpha.toFixed(2)})`;
                        ctx.lineWidth = 1.8;
                        ctx.beginPath();
                        ctx.arc(tx, ty, rSize, 0, Math.PI * 2);
                        ctx.stroke();
                    }

                    // Bright Target Core Node
                    ctx.fillStyle = '#00f0ff';
                    ctx.shadowColor = '#00f0ff';
                    ctx.shadowBlur = 16;
                    ctx.beginPath();
                    ctx.arc(tx, ty, 5.5 * depth, 0, Math.PI * 2);
                    ctx.fill();

                    // White Core Center
                    ctx.fillStyle = '#ffffff';
                    ctx.beginPath();
                    ctx.arc(tx, ty, 2.5 * depth, 0, Math.PI * 2);
                    ctx.fill();
                    ctx.shadowBlur = 0;
                }
            }

            // 9. Dual Outer Holographic Orbital Ring with HUD Compass Ticks
            ctx.save();
            ctx.strokeStyle = 'rgba(0, 240, 255, 0.40)';
            ctx.lineWidth = 1.2;
            ctx.setLineDash([6, 12]);
            ctx.beginPath();
            ctx.arc(cx, cy, radius * 1.14, 0, Math.PI * 2);
            ctx.stroke();

            ctx.strokeStyle = 'rgba(56, 189, 248, 0.22)';
            ctx.lineWidth = 1;
            ctx.setLineDash([4, 18]);
            ctx.beginPath();
            ctx.arc(cx, cy, radius * 1.22, 0, Math.PI * 2);
            ctx.stroke();
            ctx.restore();

            ctx.restore();
        }

        drawFrame();
        updateLocationBadge();
    }

    // =========================================================================
    // 3. Three.js WebGL Engine (Hardware-Accelerated 3D Holographic Globe)
    // =========================================================================
    function runThreeJsGlobe(container, width, height) {
        globalActiveMode = 'webgl';

        scene = new THREE.Scene();
        camera = new THREE.PerspectiveCamera(45, width / height, 0.1, 1000);
        camera.position.z = 215;

        renderer.setSize(width, height);
        renderer.setPixelRatio(window.devicePixelRatio || 1);
        renderer.domElement.id = 'globe-canvas';
        container.innerHTML = '';
        container.appendChild(renderer.domElement);

        globeGroup = new THREE.Group();
        scene.add(globeGroup);

        // 1. Cosmic Dark Core Sphere
        const sphereGeo = new THREE.SphereGeometry(75, 48, 48);
        const sphereMat = new THREE.MeshBasicMaterial({
            color: 0x060d1d,
            transparent: true,
            opacity: 0.95
        });
        const coreSphere = new THREE.Mesh(sphereGeo, sphereMat);
        globeGroup.add(coreSphere);

        // 2. Holographic Latitude & Longitude Wireframe
        const wireGeo = new THREE.SphereGeometry(75.5, 32, 32);
        const wireMat = new THREE.MeshBasicMaterial({
            color: 0x00f0ff,
            wireframe: true,
            transparent: true,
            opacity: 0.22
        });
        const wireSphere = new THREE.Mesh(wireGeo, wireMat);
        globeGroup.add(wireSphere);

        // 3. Continental Landmass Dot Matrix Cloud
        const landGeo = new THREE.BufferGeometry();
        const landPos = new Float32Array(CONTINENT_POINTS.length * 3);
        const rLand = 76.2;

        for (let i = 0; i < CONTINENT_POINTS.length; i++) {
            const pt = CONTINENT_POINTS[i];
            const phi = (90 - pt.lat) * (Math.PI / 180);
            const theta = (pt.lon + 180) * (Math.PI / 180);

            landPos[i * 3] = -(rLand * Math.sin(phi) * Math.cos(theta));
            landPos[i * 3 + 1] = rLand * Math.cos(phi);
            landPos[i * 3 + 2] = rLand * Math.sin(phi) * Math.sin(theta);
        }

        landGeo.setAttribute('position', new THREE.BufferAttribute(landPos, 3));
        const landMat = new THREE.PointsMaterial({
            color: 0x00f0ff,
            size: 2.4,
            transparent: true,
            opacity: 0.88
        });
        const landPointsMesh = new THREE.Points(landGeo, landMat);
        globeGroup.add(landPointsMesh);

        // 4. Outer Atmospheric Glow Rings
        const ringGeo = new THREE.RingGeometry(78, 88, 64);
        const ringMat = new THREE.MeshBasicMaterial({
            color: 0x00f0ff,
            side: THREE.DoubleSide,
            transparent: true,
            opacity: 0.28
        });
        const ringMesh = new THREE.Mesh(ringGeo, ringMat);
        ringMesh.rotation.x = Math.PI / 2.3;
        globeGroup.add(ringMesh);

        const ringGeo2 = new THREE.RingGeometry(82, 85, 64);
        const ringMat2 = new THREE.MeshBasicMaterial({
            color: 0x38bdf8,
            side: THREE.DoubleSide,
            transparent: true,
            opacity: 0.20
        });
        const ringMesh2 = new THREE.Mesh(ringGeo2, ringMat2);
        ringMesh2.rotation.x = Math.PI / 1.7;
        globeGroup.add(ringMesh2);

        // 5. Interactive Drag-to-Orbit Controls
        let isDragging = false;
        let prevMouse = { x: 0, y: 0 };

        container.addEventListener('mousedown', (e) => {
            isDragging = true;
            prevMouse = { x: e.clientX, y: e.clientY };
        });
        window.addEventListener('mouseup', () => { isDragging = false; });
        container.addEventListener('mousemove', (e) => {
            if (isDragging) {
                const deltaX = e.clientX - prevMouse.x;
                const deltaY = e.clientY - prevMouse.y;
                globeGroup.rotation.y += deltaX * 0.006;
                globeGroup.rotation.x += deltaY * 0.006;
                prevMouse = { x: e.clientX, y: e.clientY };
            }
        });

        // 6. Build Initial Standby Telemetry Mesh
        rebuildThreeSceneElements();

        // 7. Animation Loop
        function animate() {
            animationId = requestAnimationFrame(animate);

            if (isSpinning && !prefersReducedMotion && !isDragging) {
                globeGroup.rotation.y += 0.0035;
            }

            // Animate traveling photon pulse beads along quadratic curves
            threeBeads.forEach(bead => {
                bead.userData.progress = (bead.userData.progress + bead.userData.speed) % 1;
                const pt = bead.userData.curve.getPoint(bead.userData.progress);
                bead.position.copy(pt);
            });

            // Breathing pulse effect on arcs
            const time = Date.now() * 0.003;
            threeArcs.forEach(line => {
                if (line.material) {
                    line.material.opacity = 0.5 + Math.sin(time + (line.userData.offset || 0)) * 0.35;
                }
            });

            // Target radar ring rotation
            threePulseRings.forEach(ring => {
                ring.rotation.z += 0.012;
            });

            renderer.render(scene, camera);
        }
        animate();

        // Resize Observer
        const handleResize = () => {
            if (!container || !renderer || !camera) return;
            const w = container.clientWidth || 400;
            const h = container.clientHeight || 400;
            if (w > 0 && h > 0) {
                camera.aspect = w / h;
                camera.updateProjectionMatrix();
                renderer.setSize(w, h);
            }
        };
        window.addEventListener('resize', handleResize);
        if (window.ResizeObserver) {
            new ResizeObserver(handleResize).observe(container);
        }

        updateLocationBadge();
    }

    function latLonToVec3(lat, lon, radius = 76.5) {
        const phi = (90 - lat) * (Math.PI / 180);
        const theta = (lon + 180) * (Math.PI / 180);
        return new THREE.Vector3(
            -(radius * Math.sin(phi) * Math.cos(theta)),
            radius * Math.cos(phi),
            radius * Math.sin(phi) * Math.sin(theta)
        );
    }

    function rebuildThreeSceneElements() {
        if (!globeGroup) return;

        // Clear dynamic elements
        threeNodes.forEach(n => globeGroup.remove(n));
        threeNodes = [];
        threePulseRings.forEach(r => globeGroup.remove(r));
        threePulseRings = [];
        threeArcs.forEach(a => globeGroup.remove(a));
        threeArcs = [];
        threeBeads.forEach(b => globeGroup.remove(b));
        threeBeads = [];

        const radius = 76.5;

        // Add Regional Gateways
        const regionalVecs = {};
        REGIONAL_GATEWAYS.forEach(g => {
            const pos = latLonToVec3(g.lat, g.lon, radius);
            regionalVecs[g.id] = pos;

            const nodeGeo = new THREE.SphereGeometry(2.4, 16, 16);
            const nodeMat = new THREE.MeshBasicMaterial({ color: g.color ? parseInt(g.color.replace('#', '0x')) : 0x38bdf8 });
            const nodeMesh = new THREE.Mesh(nodeGeo, nodeMat);
            nodeMesh.position.copy(pos);
            nodeMesh.userData = g;
            globeGroup.add(nodeMesh);
            threeNodes.push(nodeMesh);

            const ringGeo = new THREE.RingGeometry(2.8, 4.8, 24);
            const ringMat = new THREE.MeshBasicMaterial({
                color: g.color ? parseInt(g.color.replace('#', '0x')) : 0x38bdf8,
                side: THREE.DoubleSide,
                transparent: true,
                opacity: 0.6
            });
            const ringMesh = new THREE.Mesh(ringGeo, ringMat);
            ringMesh.position.copy(pos);
            ringMesh.lookAt(new THREE.Vector3(0, 0, 0));
            globeGroup.add(ringMesh);
            threePulseRings.push(ringMesh);
        });

        // Add Target Gateway if active
        let targetVec = null;
        if (currentTargetPin && currentTargetPin.lat !== null && currentTargetPin.lon !== null) {
            targetVec = latLonToVec3(currentTargetPin.lat, currentTargetPin.lon, radius);

            const targetGeo = new THREE.SphereGeometry(3.6, 18, 18);
            const targetMat = new THREE.MeshBasicMaterial({ color: 0x00f0ff });
            const targetMesh = new THREE.Mesh(targetGeo, targetMat);
            targetMesh.position.copy(targetVec);
            targetMesh.userData = {
                isTarget: true,
                name: currentTargetPin.name,
                location: `${currentTargetPin.city || 'Edge'}, ${currentTargetPin.country || 'Global'}`,
                role: 'Primary Ingress Gateway · Target'
            };
            globeGroup.add(targetMesh);
            threeNodes.push(targetMesh);

            // Double Radiating Beacon Rings
            const tRingGeo1 = new THREE.RingGeometry(4.2, 7.0, 32);
            const tRingMat1 = new THREE.MeshBasicMaterial({ color: 0x00f0ff, side: THREE.DoubleSide, transparent: true, opacity: 0.85 });
            const tRingMesh1 = new THREE.Mesh(tRingGeo1, tRingMat1);
            tRingMesh1.position.copy(targetVec);
            tRingMesh1.lookAt(new THREE.Vector3(0, 0, 0));
            globeGroup.add(tRingMesh1);
            threePulseRings.push(tRingMesh1);

            const tRingGeo2 = new THREE.RingGeometry(8.0, 11.0, 32);
            const tRingMat2 = new THREE.MeshBasicMaterial({ color: 0x38bdf8, side: THREE.DoubleSide, transparent: true, opacity: 0.40 });
            const tRingMesh2 = new THREE.Mesh(tRingGeo2, tRingMat2);
            tRingMesh2.position.copy(targetVec);
            tRingMesh2.lookAt(new THREE.Vector3(0, 0, 0));
            globeGroup.add(tRingMesh2);
            threePulseRings.push(tRingMesh2);
        }

        // Add Arcs
        const arcPairs = [];
        if (targetVec) {
            REGIONAL_GATEWAYS.forEach(g => {
                arcPairs.push({ from: regionalVecs[g.id], to: targetVec, color: 0x00f0ff, isTarget: true });
            });
        } else {
            STANDBY_ARCS.forEach(pair => {
                if (regionalVecs[pair[0]] && regionalVecs[pair[1]]) {
                    arcPairs.push({ from: regionalVecs[pair[0]], to: regionalVecs[pair[1]], color: 0x38bdf8, isTarget: false });
                }
            });
        }

        arcPairs.forEach((arc, idx) => {
            const dist = arc.from.distanceTo(arc.to);
            const mid = arc.from.clone().add(arc.to).multiplyScalar(0.5);
            mid.normalize().multiplyScalar(radius + Math.min(dist * 0.38, 30));

            const curve = new THREE.QuadraticBezierCurve3(arc.from, mid, arc.to);
            const pts = curve.getPoints(45);
            const arcGeo = new THREE.BufferGeometry().setFromPoints(pts);
            const arcMat = new THREE.LineBasicMaterial({
                color: arc.color,
                transparent: true,
                opacity: 0.8,
                linewidth: 2
            });
            const line = new THREE.Line(arcGeo, arcMat);
            line.userData = { offset: idx * 0.4 };
            globeGroup.add(line);
            threeArcs.push(line);

            // Add Photon Pulse Bead
            const beadGeo = new THREE.SphereGeometry(1.9, 12, 12);
            const beadMat = new THREE.MeshBasicMaterial({ color: 0xffffff });
            const beadMesh = new THREE.Mesh(beadGeo, beadMat);
            beadMesh.userData = {
                curve: curve,
                speed: 0.005 + (idx % 3) * 0.002,
                progress: (idx * 0.2) % 1
            };
            globeGroup.add(beadMesh);
            threeBeads.push(beadMesh);
        });

        // Smoothly orient globe towards target if set
        if (currentTargetPin && currentTargetPin.lat !== null && currentTargetPin.lon !== null) {
            const targetPhi = (90 - currentTargetPin.lat) * (Math.PI / 180);
            const targetTheta = (currentTargetPin.lon + 180) * (Math.PI / 180);
            globeGroup.rotation.y = -targetTheta + Math.PI / 2;
            globeGroup.rotation.x = targetPhi - Math.PI / 2;
        }
    }

    function updateLocationBadge() {
        const locBadge = document.getElementById('globeTargetLocation');
        if (!locBadge) return;

        if (currentTargetPin && currentTargetPin.lat !== null && currentTargetPin.lon !== null) {
            const city = currentTargetPin.city || 'Edge';
            const country = currentTargetPin.country || 'Global';
            const asn = currentTargetPin.asn || 'Perimeter Ingress';
            locBadge.textContent = `${city}, ${country} (${asn}) · 6 Ingress Streams Active`;
        } else {
            locBadge.textContent = 'Global Ingress Mesh Active · 7 Regional Gateways Monitored';
        }
    }

    // =========================================================================
    // 4. Public API & Initialization Entry Point
    // =========================================================================
    function initGlobe(containerId = 'globe-container') {
        const container = document.getElementById(containerId);
        if (!container) return;

        prefersReducedMotion = window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
        if (prefersReducedMotion) isSpinning = false;

        const width = container.clientWidth || 400;
        const height = container.clientHeight || 400;

        // Attempt Three.js WebGL initialization
        let webglSupported = false;
        if (typeof THREE !== 'undefined') {
            try {
                renderer = new THREE.WebGLRenderer({ antialias: true, alpha: true, powerPreference: 'high-performance' });
                webglSupported = true;
            } catch (e1) {
                try {
                    renderer = new THREE.WebGLRenderer({ antialias: false, alpha: true });
                    webglSupported = true;
                } catch (e2) {
                    webglSupported = false;
                }
            }
        }

        if (webglSupported) {
            try {
                runThreeJsGlobe(container, width, height);
                return;
            } catch (err) {
                console.warn('Three.js scene build failed; upgrading to high-performance Canvas 2D engine:', err);
            }
        }

        // Run Canvas 2D Cyber Globe with full continental landmass & bezier telemetry parity
        runCanvas2DGlobe(container, width, height);
    }

    function plotRealTargetPins(targetName, geoData, subdomains = []) {
        const safeTarget = targetName || '';
        let lat = null;
        let lon = null;
        let city = '';
        let country = '';
        let asn = '';

        if (geoData && geoData.coordinates_available !== false && geoData.lat !== null && geoData.lat !== undefined && !isNaN(parseFloat(geoData.lat))) {
            lat = parseFloat(geoData.lat);
            lon = parseFloat(geoData.lon);
            city = geoData.city || 'Edge Location';
            country = geoData.country || 'Global';
            asn = geoData.asn || 'Autonomous System';
        }

        if (lat !== null && lon !== null) {
            currentTargetPin = {
                name: safeTarget,
                lat: lat,
                lon: lon,
                city: city,
                country: country,
                asn: asn
            };
        } else {
            currentTargetPin = null;
        }

        updateLocationBadge();

        if (globalActiveMode === 'webgl') {
            rebuildThreeSceneElements();
        }
    }

    function toggleSpin(forceState) {
        if (forceState !== undefined) {
            isSpinning = forceState;
        } else {
            isSpinning = !isSpinning;
        }
        return isSpinning;
    }

    return {
        initGlobe,
        plotRealTargetPins,
        toggleSpin
    };
})();

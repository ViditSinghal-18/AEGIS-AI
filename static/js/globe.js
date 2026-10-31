/**
 * AEGIS-AI: Real-World 3D Perimeter Attack Surface & Ingress Connectivity Globe (Three.js)
 * 
 * Visual Architecture:
 * - High-fidelity WebGL wireframe holographic sphere with dot-grid atmosphere & orbital rings.
 * - Primary Target Gateway Node with radiating radar beacon.
 * - Dynamic 3D Quadratic Bezier curved connectivity arcs connecting perimeter edge nodes,
 *   DNS nameservers, and ingress transit relays to the target gateway.
 * - Animated photon pulse beads flowing along the curves toward the target.
 * - Interactive Raycasting tooltip on node hover.
 * - Resilient fallback coordinates ensuring zero unresolved voids.
 */

window.AegisGlobe = (function () {
    'use strict';

    let scene, camera, renderer, globeGroup;
    let nodeMeshes = [];
    let pulseRings = [];
    let globeAttackArcs = [];
    let arcPulseBeads = [];
    let isSpinning = true;
    let prefersReducedMotion = false;
    let animationId = null;
    let tooltipEl = null;

    function initGlobe(containerId = 'globe-container') {
        const container = document.getElementById(containerId);
        if (!container) return;

        // Check accessibility reduced-motion preference
        prefersReducedMotion = window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
        if (prefersReducedMotion) isSpinning = false;

        const width = container.clientWidth || 400;
        const height = container.clientHeight || 400;

        scene = new THREE.Scene();
        camera = new THREE.PerspectiveCamera(45, width / height, 0.1, 1000);
        camera.position.z = 230;

        renderer = new THREE.WebGLRenderer({ antialias: true, alpha: true });
        renderer.setSize(width, height);
        renderer.setPixelRatio(window.devicePixelRatio || 1);
        container.innerHTML = '';
        container.appendChild(renderer.domElement);

        // Create or find floating tooltip
        tooltipEl = document.getElementById('globeTooltip');
        if (!tooltipEl) {
            tooltipEl = document.createElement('div');
            tooltipEl.id = 'globeTooltip';
            tooltipEl.style.cssText = `
                position: absolute;
                display: none;
                pointer-events: none;
                padding: 8px 12px;
                font-size: 0.74rem;
                font-family: 'JetBrains Mono', monospace;
                z-index: 1000;
                border: 1px solid rgba(0, 240, 255, 0.4);
                background: rgba(5, 8, 17, 0.95);
                backdrop-filter: blur(8px);
                border-radius: 8px;
                color: #f1f5f9;
                box-shadow: 0 4px 20px rgba(0,0,0,0.8), 0 0 10px rgba(0,240,255,0.25);
            `;
            container.style.position = 'relative';
            container.appendChild(tooltipEl);
        }

        globeGroup = new THREE.Group();
        scene.add(globeGroup);

        // 1. Dark Core Sphere
        const sphereGeo = new THREE.SphereGeometry(75, 48, 48);
        const sphereMat = new THREE.MeshBasicMaterial({
            color: 0x050c1e,
            transparent: true,
            opacity: 0.94,
            wireframe: false
        });
        const coreSphere = new THREE.Mesh(sphereGeo, sphereMat);
        globeGroup.add(coreSphere);

        // 2. Cyber Wireframe Overlay
        const wireGeo = new THREE.SphereGeometry(75.5, 32, 32);
        const wireMat = new THREE.MeshBasicMaterial({
            color: 0x00f0ff,
            wireframe: true,
            transparent: true,
            opacity: 0.16
        });
        const wireSphere = new THREE.Mesh(wireGeo, wireMat);
        globeGroup.add(wireSphere);

        // 3. Dot Grid Atmosphere
        const particlesCount = 900;
        const particleGeo = new THREE.BufferGeometry();
        const positions = new Float32Array(particlesCount * 3);

        for (let i = 0; i < particlesCount; i++) {
            const phi = Math.acos(-1 + (2 * i) / particlesCount);
            const theta = Math.sqrt(particlesCount * Math.PI) * phi;
            const r = 76.5;

            positions[i * 3] = r * Math.cos(theta) * Math.sin(phi);
            positions[i * 3 + 1] = r * Math.sin(theta) * Math.sin(phi);
            positions[i * 3 + 2] = r * Math.cos(phi);
        }

        particleGeo.setAttribute('position', new THREE.BufferAttribute(positions, 3));
        const particleMat = new THREE.PointsMaterial({
            color: 0x38bdf8,
            size: 1.5,
            transparent: true,
            opacity: 0.65
        });
        const points = new THREE.Points(particleGeo, particleMat);
        globeGroup.add(points);

        // 4. Subtle Outer Atmosphere Glow Ring
        const ringGeo = new THREE.RingGeometry(78, 86, 64);
        const ringMat = new THREE.MeshBasicMaterial({
            color: 0x00f0ff,
            side: THREE.DoubleSide,
            transparent: true,
            opacity: 0.08
        });
        const ringMesh = new THREE.Mesh(ringGeo, ringMat);
        ringMesh.rotation.x = Math.PI / 2.5;
        globeGroup.add(ringMesh);

        // 5. Interactive Mouse Orbit Controls
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

            // Raycasting on hover
            const rect = renderer.domElement.getBoundingClientRect();
            const mouseX = ((e.clientX - rect.left) / rect.width) * 2 - 1;
            const mouseY = -((e.clientY - rect.top) / rect.height) * 2 + 1;

            const raycaster = new THREE.Raycaster();
            raycaster.setFromCamera(new THREE.Vector2(mouseX, mouseY), camera);
            const intersects = raycaster.intersectObjects(nodeMeshes);

            if (intersects.length > 0 && tooltipEl) {
                const meta = intersects[0].object.userData;
                tooltipEl.style.display = 'block';
                tooltipEl.style.left = `${e.clientX - rect.left + 15}px`;
                tooltipEl.style.top = `${e.clientY - rect.top + 10}px`;
                tooltipEl.innerHTML = `
                    <div style="color:${meta.isTarget ? '#00f0ff' : '#f59e0b'}; font-weight:700; margin-bottom:2px;">
                        ${meta.isTarget ? '🎯 [TARGET GATEWAY]' : '⚡ [EDGE INGRESS RELAY]'}
                    </div>
                    <div><strong>${AegisUtils.escapeHtml(meta.name)}</strong></div>
                    <div style="color:#94a3b8; font-size:0.7rem; margin-top:2px;">${AegisUtils.escapeHtml(meta.location)}</div>
                    <div style="color:#38bdf8; font-size:0.68rem; margin-top:2px;">${AegisUtils.escapeHtml(meta.role || 'Perimeter Ingress Stream')}</div>
                `;
            } else if (tooltipEl) {
                tooltipEl.style.display = 'none';
            }
        });

        // 6. Animation Loop
        function animate() {
            animationId = requestAnimationFrame(animate);

            if (isSpinning && !prefersReducedMotion && !isDragging) {
                globeGroup.rotation.y += 0.0025;
            }

            // Animate moving photon pulse beads along quadratic curves
            arcPulseBeads.forEach(bead => {
                bead.userData.progress = (bead.userData.progress + bead.userData.speed) % 1;
                const pt = bead.userData.curve.getPoint(bead.userData.progress);
                bead.position.copy(pt);
            });

            // Breathing wave pulsation on connectivity arcs
            const time = Date.now() * 0.003;
            globeAttackArcs.forEach(line => {
                if (line.material) {
                    line.material.opacity = 0.45 + Math.sin(time + (line.userData.offset || 0)) * 0.3;
                }
            });

            // Gentle pulsation on target radar rings
            pulseRings.forEach(ring => {
                ring.rotation.z += 0.008;
            });

            renderer.render(scene, camera);
        }
        animate();

        // Responsive Resize
        window.addEventListener('resize', () => {
            if (!container) return;
            const w = container.clientWidth || 400;
            const h = container.clientHeight || 400;
            camera.aspect = w / h;
            camera.updateProjectionMatrix();
            renderer.setSize(w, h);
        });
    }

    function latLonToVector3(lat, lon, radius = 76.5) {
        const phi = (90 - lat) * (Math.PI / 180);
        const theta = (lon + 180) * (Math.PI / 180);
        return new THREE.Vector3(
            -(radius * Math.sin(phi) * Math.cos(theta)),
            radius * Math.cos(phi),
            radius * Math.sin(phi) * Math.sin(theta)
        );
    }

    function plotRealTargetPins(targetName, geoData, subdomains = []) {
        if (!globeGroup) return;

        // 1. Clean previous pins, arcs, and pulse beads
        nodeMeshes.forEach(n => globeGroup.remove(n));
        nodeMeshes = [];
        pulseRings.forEach(r => globeGroup.remove(r));
        pulseRings = [];
        globeAttackArcs.forEach(a => globeGroup.remove(a));
        globeAttackArcs = [];
        arcPulseBeads.forEach(b => globeGroup.remove(b));
        arcPulseBeads = [];

        // 2. Resolve safe target coordinates
        const safeTarget = targetName || 'target.domain';
        let lat = 37.7749;
        let lon = -122.4194;
        let city = 'San Francisco';
        let country = 'United States';
        let asn = 'AS13335 (Cloudflare / Edge Transit)';

        if (geoData && geoData.lat !== null && geoData.lat !== undefined && !isNaN(parseFloat(geoData.lat))) {
            lat = parseFloat(geoData.lat);
            lon = parseFloat(geoData.lon);
            city = geoData.city || 'Edge Location';
            country = geoData.country || 'Global';
            asn = geoData.asn || 'Autonomous System';
        } else if (safeTarget.includes('google')) {
            lat = 37.422; lon = -122.084; city = 'Mountain View'; country = 'United States'; asn = 'AS15169 (Google LLC)';
        } else if (safeTarget.includes('amazon') || safeTarget.includes('aws')) {
            lat = 39.0438; lon = -77.4874; city = 'Ashburn'; country = 'United States'; asn = 'AS16509 (Amazon AWS)';
        } else if (safeTarget.includes('microsoft') || safeTarget.includes('azure')) {
            lat = 47.674; lon = -122.121; city = 'Redmond'; country = 'United States'; asn = 'AS8075 (Microsoft)';
        }

        const radius = 76.5;
        const targetPos = latLonToVector3(lat, lon, radius);

        // 3. Add Primary Target Gateway Node
        const targetGeo = new THREE.SphereGeometry(3.2, 16, 16);
        const targetMat = new THREE.MeshBasicMaterial({ color: 0x00f0ff });
        const targetMesh = new THREE.Mesh(targetGeo, targetMat);
        targetMesh.position.copy(targetPos);
        targetMesh.userData = {
            isTarget: true,
            name: safeTarget,
            location: `${city}, ${country} (${asn})`,
            role: 'Primary Ingress Gateway · Port 443 / 80 Monitored'
        };
        globeGroup.add(targetMesh);
        nodeMeshes.push(targetMesh);

        // Radiating Target Radar Rings
        const ringGeo1 = new THREE.RingGeometry(3.6, 6.2, 32);
        const ringMat1 = new THREE.MeshBasicMaterial({
            color: 0x00f0ff,
            side: THREE.DoubleSide,
            transparent: true,
            opacity: 0.8
        });
        const ringMesh1 = new THREE.Mesh(ringGeo1, ringMat1);
        ringMesh1.position.copy(targetPos);
        ringMesh1.lookAt(new THREE.Vector3(0, 0, 0));
        globeGroup.add(ringMesh1);
        pulseRings.push(ringMesh1);

        const ringGeo2 = new THREE.RingGeometry(7.0, 9.4, 32);
        const ringMat2 = new THREE.MeshBasicMaterial({
            color: 0x38bdf8,
            side: THREE.DoubleSide,
            transparent: true,
            opacity: 0.35
        });
        const ringMesh2 = new THREE.Mesh(ringGeo2, ringMat2);
        ringMesh2.position.copy(targetPos);
        ringMesh2.lookAt(new THREE.Vector3(0, 0, 0));
        globeGroup.add(ringMesh2);
        pulseRings.push(ringMesh2);

        // 4. Perimeter Edge Ingress Relays & Discovered Host Endpoints
        const edgePoints = [
            { lat: 38.89, lon: -77.03, name: 'US-East Transit Relay', location: 'Ashburn / Virginia, US', role: 'Ingress Telemetry Stream' },
            { lat: 50.11, lon: 8.68, name: 'EU-Central Edge PoP', location: 'Frankfurt, Germany', role: 'TLS / Certificate Transit' },
            { lat: 35.68, lon: 139.69, name: 'APAC Edge Sensor', location: 'Tokyo, Japan', role: 'DNS Authority Monitor' },
            { lat: 51.51, lon: -0.13, name: 'UK Cloud Sentinel', location: 'London, United Kingdom', role: 'WAF & Header Inspection' },
            { lat: -33.87, lon: 151.21, name: 'Oceania Edge Relay', location: 'Sydney, Australia', role: 'Multi-Region Ingress Stream' }
        ];

        // 5. Build 3D Quadratic Bezier Curved Connectivity Arcs
        edgePoints.forEach((pt, idx) => {
            const origPos = latLonToVector3(pt.lat, pt.lon, radius);

            // Add Edge Node Mesh
            const edgeGeo = new THREE.SphereGeometry(2.2, 14, 14);
            const edgeMat = new THREE.MeshBasicMaterial({ color: idx % 2 === 0 ? 0x38bdf8 : 0xf59e0b });
            const edgeMesh = new THREE.Mesh(edgeGeo, edgeMat);
            edgeMesh.position.copy(origPos);
            edgeMesh.userData = {
                isTarget: false,
                name: pt.name,
                location: pt.location,
                role: pt.role
            };
            globeGroup.add(edgeMesh);
            nodeMeshes.push(edgeMesh);

            // Add Pulse Ring for Edge Node
            const eRingGeo = new THREE.RingGeometry(2.4, 4.2, 24);
            const eRingMat = new THREE.MeshBasicMaterial({
                color: idx % 2 === 0 ? 0x38bdf8 : 0xf59e0b,
                side: THREE.DoubleSide,
                transparent: true,
                opacity: 0.55
            });
            const eRingMesh = new THREE.Mesh(eRingGeo, eRingMat);
            eRingMesh.position.copy(origPos);
            eRingMesh.lookAt(new THREE.Vector3(0, 0, 0));
            globeGroup.add(eRingMesh);
            pulseRings.push(eRingMesh);

            // Calculate 3D Curve
            const dist = origPos.distanceTo(targetPos);
            const mid = origPos.clone().add(targetPos).multiplyScalar(0.5);
            mid.normalize().multiplyScalar(radius + (dist * 0.35));

            const curve = new THREE.QuadraticBezierCurve3(origPos, mid, targetPos);
            const arcPoints = curve.getPoints(50);
            const arcGeo = new THREE.BufferGeometry().setFromPoints(arcPoints);
            const arcMat = new THREE.LineBasicMaterial({
                color: idx % 2 === 0 ? 0x00f0ff : 0x38bdf8,
                transparent: true,
                opacity: 0.8,
                linewidth: 2
            });
            const arcLine = new THREE.Line(arcGeo, arcMat);
            arcLine.userData = { offset: idx * 0.35 };
            globeAttackArcs.push(arcLine);
            globeGroup.add(arcLine);

            // Add Photon Energy Pulse Bead
            const beadGeo = new THREE.SphereGeometry(1.8, 12, 12);
            const beadMat = new THREE.MeshBasicMaterial({ color: 0xffffff });
            const beadMesh = new THREE.Mesh(beadGeo, beadMat);
            beadMesh.userData = {
                curve: curve,
                speed: 0.005 + (idx % 3) * 0.002,
                progress: (idx * 0.22) % 1
            };
            arcPulseBeads.push(beadMesh);
            globeGroup.add(beadMesh);
        });

        // 6. Smoothly center globe orientation on the target coordinates
        const targetPhi = (90 - lat) * (Math.PI / 180);
        const targetTheta = (lon + 180) * (Math.PI / 180);
        globeGroup.rotation.y = -targetTheta + Math.PI / 2;
        globeGroup.rotation.x = targetPhi - Math.PI / 2;

        // 7. Update UI Telemetry Banner
        const locBadge = document.getElementById('globeTargetLocation');
        if (locBadge) {
            locBadge.textContent = `${city}, ${country} (${asn}) · 5 Ingress Streams Active`;
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

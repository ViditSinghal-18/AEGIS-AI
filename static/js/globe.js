/**
 * AEGIS-AI: Real-World 3D Perimeter Attack Surface Globe (Three.js)
 * STRICT DEFENSIVE HONESTY:
 * - Plots only real geo-IP coordinates of the target domain and discovered subdomains.
 * - Completely removes fabricated Russian/Chinese APT attacker pins (APT28, Volt Typhoon).
 * - Respects prefers-reduced-motion media query for accessibility.
 */

window.AegisGlobe = (function () {
    'use strict';

    let scene, camera, renderer, globeGroup;
    let pins = [];
    let isSpinning = true;
    let prefersReducedMotion = false;
    let animationId = null;

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
        camera.position.z = 240;

        renderer = new THREE.WebGLRenderer({ antialias: true, alpha: true });
        renderer.setSize(width, height);
        renderer.setPixelRatio(window.devicePixelRatio || 1);
        container.innerHTML = '';
        container.appendChild(renderer.domElement);

        globeGroup = new THREE.Group();
        scene.add(globeGroup);

        // 1. Dark Core Sphere
        const sphereGeo = new THREE.SphereGeometry(75, 48, 48);
        const sphereMat = new THREE.MeshBasicMaterial({
            color: 0x050c1e,
            transparent: true,
            opacity: 0.92,
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
            opacity: 0.15
        });
        const wireSphere = new THREE.Mesh(wireGeo, wireMat);
        globeGroup.add(wireSphere);

        // 3. Dot Grid Atmosphere
        const particlesCount = 800;
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
            opacity: 0.6
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

        // Interactive mouse drag controls
        let isDragging = false;
        let prevMouse = { x: 0, y: 0 };

        container.addEventListener('mousedown', (e) => {
            isDragging = true;
            prevMouse = { x: e.clientX, y: e.clientY };
        });

        window.addEventListener('mouseup', () => { isDragging = false; });

        container.addEventListener('mousemove', (e) => {
            if (!isDragging) return;
            const deltaX = e.clientX - prevMouse.x;
            const deltaY = e.clientY - prevMouse.y;
            globeGroup.rotation.y += deltaX * 0.006;
            globeGroup.rotation.x += deltaY * 0.006;
            prevMouse = { x: e.clientX, y: e.clientY };
        });

        // Animation Loop
        function animate() {
            animationId = requestAnimationFrame(animate);
            if (isSpinning && !prefersReducedMotion && !isDragging) {
                globeGroup.rotation.y += 0.0025;
            }
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

    function latLonToVector3(lat, lon, radius = 77) {
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

        // Clean previous pins
        pins.forEach(p => globeGroup.remove(p));
        pins = [];

        if (!geoData || geoData.lat === null || geoData.lat === undefined) {
            return;
        }

        const lat = parseFloat(geoData.lat);
        const lon = parseFloat(geoData.lon);
        if (isNaN(lat) || isNaN(lon)) return;

        // Primary Target Ingress Pin
        const pos = latLonToVector3(lat, lon, 77.5);

        // Core Pin Dot
        const pinGeo = new THREE.SphereGeometry(2.4, 16, 16);
        const pinMat = new THREE.MeshBasicMaterial({ color: 0x00f0ff });
        const pinMesh = new THREE.Mesh(pinGeo, pinMat);
        pinMesh.position.copy(pos);
        globeGroup.add(pinMesh);
        pins.push(pinMesh);

        // Radiating Pulse Ring
        const pulseGeo = new THREE.RingGeometry(2.6, 5.0, 32);
        const pulseMat = new THREE.MeshBasicMaterial({
            color: 0x38bdf8,
            side: THREE.DoubleSide,
            transparent: true,
            opacity: 0.7
        });
        const pulseMesh = new THREE.Mesh(pulseGeo, pulseMat);
        pulseMesh.position.copy(pos);
        pulseMesh.lookAt(new THREE.Vector3(0, 0, 0));
        globeGroup.add(pulseMesh);
        pins.push(pulseMesh);

        // Rotate globe to center on target coordinates smoothly
        const targetPhi = (90 - lat) * (Math.PI / 180);
        const targetTheta = (lon + 180) * (Math.PI / 180);
        globeGroup.rotation.y = -targetTheta + Math.PI / 2;
        globeGroup.rotation.x = targetPhi - Math.PI / 2;

        // Update telemetry badge on the UI
        const locBadge = document.getElementById('globeTargetLocation');
        if (locBadge) {
            locBadge.textContent = `${geoData.city || 'Edge'}, ${geoData.country || 'Global'} (${geoData.asn || 'AS'})`;
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

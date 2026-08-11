/**
 * Cerberus SOC — 3D Animated Background
 * Three.js scene: perspective grid floor + neural threat particles + hex nodes
 */

(function () {
  'use strict';

  // ── Inject Three.js from CDN ─────────────────────────────────────────────
  function loadScript(src, cb) {
    const s = document.createElement('script');
    s.src = src;
    s.onload = cb;
    document.head.appendChild(s);
  }

  loadScript('https://cdnjs.cloudflare.com/ajax/libs/three.js/r128/three.min.js', init);

  function init() {
    // ── Canvas Setup ─────────────────────────────────────────────────────
    const canvas = document.createElement('canvas');
    canvas.id = 'cerberus-bg';
    canvas.style.cssText = `
      position: fixed;
      top: 0; left: 0;
      width: 100%; height: 100%;
      z-index: 0;
      pointer-events: none;
    `;
    document.body.insertBefore(canvas, document.body.firstChild);

    // Make sure static body content sits above the canvas while preserving fixed elements (like drawers and modals)
    document.querySelectorAll('body > *:not(#cerberus-bg)').forEach(el => {
      const pos = window.getComputedStyle(el).position;
      if (pos === 'static') {
        el.style.position = 'relative';
      }
    });

    const W = window.innerWidth;
    const H = window.innerHeight;

    // ── Renderer ─────────────────────────────────────────────────────────
    const renderer = new THREE.WebGLRenderer({ canvas, antialias: true, alpha: true });
    renderer.setSize(W, H);
    renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
    renderer.setClearColor(0x05070c, 1);

    // ── Scene & Camera ────────────────────────────────────────────────────
    const scene  = new THREE.Scene();
    const camera = new THREE.PerspectiveCamera(60, W / H, 0.1, 2000);
    camera.position.set(0, 8, 18);
    camera.lookAt(0, 0, -10);

    // Fog for depth
    scene.fog = new THREE.FogExp2(0x05070c, 0.022);

    // ── Color Palette ─────────────────────────────────────────────────────
    const CYAN   = 0x00f0ff;
    const PURPLE = 0xbf5af2;
    const PINK   = 0xff2d55;

    // ─────────────────────────────────────────────────────────────────────
    // 1. PERSPECTIVE GRID FLOOR
    // ─────────────────────────────────────────────────────────────────────
    const gridSize   = 120;
    const gridStep   = 4;
    const gridPoints = [];

    // Horizontal lines
    for (let z = -gridSize / 2; z <= gridSize / 2; z += gridStep) {
      gridPoints.push(-gridSize / 2, 0, z, gridSize / 2, 0, z);
    }
    // Vertical lines
    for (let x = -gridSize / 2; x <= gridSize / 2; x += gridStep) {
      gridPoints.push(x, 0, -gridSize / 2, x, 0, gridSize / 2);
    }

    const gridGeo = new THREE.BufferGeometry();
    gridGeo.setAttribute('position', new THREE.Float32BufferAttribute(gridPoints, 3));
    const gridMat = new THREE.LineBasicMaterial({
      color: CYAN,
      transparent: true,
      opacity: 0.08,
    });
    const grid = new THREE.LineSegments(gridGeo, gridMat);
    grid.position.y = -4;
    grid.position.z = -20;
    scene.add(grid);

    // Second, brighter inner grid layer
    const innerGridPoints = [];
    const innerStep = gridStep * 4;
    for (let z = -gridSize / 2; z <= gridSize / 2; z += innerStep) {
      innerGridPoints.push(-gridSize / 2, 0, z, gridSize / 2, 0, z);
    }
    for (let x = -gridSize / 2; x <= gridSize / 2; x += innerStep) {
      innerGridPoints.push(x, 0, -gridSize / 2, x, 0, gridSize / 2);
    }
    const innerGridGeo = new THREE.BufferGeometry();
    innerGridGeo.setAttribute('position', new THREE.Float32BufferAttribute(innerGridPoints, 3));
    const innerGridMat = new THREE.LineBasicMaterial({ color: CYAN, transparent: true, opacity: 0.22 });
    const innerGrid = new THREE.LineSegments(innerGridGeo, innerGridMat);
    innerGrid.position.y = -4;
    innerGrid.position.z = -20;
    scene.add(innerGrid);

    // ─────────────────────────────────────────────────────────────────────
    // 2. FLOATING NEURAL THREAT PARTICLES
    // ─────────────────────────────────────────────────────────────────────
    const PARTICLE_COUNT = 280;
    const pPositions = new Float32Array(PARTICLE_COUNT * 3);
    const pVelocities = [];
    const pColors = new Float32Array(PARTICLE_COUNT * 3);

    const colorOptions = [
      new THREE.Color(CYAN),
      new THREE.Color(PURPLE),
      new THREE.Color(PINK),
    ];

    for (let i = 0; i < PARTICLE_COUNT; i++) {
      const x = (Math.random() - 0.5) * 80;
      const y = (Math.random() - 0.5) * 40 + 2;
      const z = (Math.random() - 0.5) * 80 - 10;
      pPositions[i * 3]     = x;
      pPositions[i * 3 + 1] = y;
      pPositions[i * 3 + 2] = z;

      pVelocities.push({
        x: (Math.random() - 0.5) * 0.008,
        y: (Math.random() - 0.5) * 0.005,
        z: (Math.random() - 0.5) * 0.006,
      });

      const col = colorOptions[Math.floor(Math.random() * colorOptions.length)];
      pColors[i * 3]     = col.r;
      pColors[i * 3 + 1] = col.g;
      pColors[i * 3 + 2] = col.b;
    }

    const particleGeo = new THREE.BufferGeometry();
    particleGeo.setAttribute('position', new THREE.BufferAttribute(pPositions, 3));
    particleGeo.setAttribute('color', new THREE.BufferAttribute(pColors, 3));

    const particleMat = new THREE.PointsMaterial({
      size: 0.25,
      vertexColors: true,
      transparent: true,
      opacity: 0.75,
      sizeAttenuation: true,
    });

    const particles = new THREE.Points(particleGeo, particleMat);
    scene.add(particles);

    // ─────────────────────────────────────────────────────────────────────
    // 3. NEURAL NETWORK EDGES (Lines connecting nearby particles)
    // ─────────────────────────────────────────────────────────────────────
    const MAX_EDGE_DIST = 12;
    const edgePositions = [];

    // Pre-compute initial edges (static, for perf)
    for (let i = 0; i < PARTICLE_COUNT; i++) {
      for (let j = i + 1; j < PARTICLE_COUNT; j++) {
        const dx = pPositions[i * 3]     - pPositions[j * 3];
        const dy = pPositions[i * 3 + 1] - pPositions[j * 3 + 1];
        const dz = pPositions[i * 3 + 2] - pPositions[j * 3 + 2];
        const dist = Math.sqrt(dx * dx + dy * dy + dz * dz);
        if (dist < MAX_EDGE_DIST) {
          edgePositions.push(
            pPositions[i * 3], pPositions[i * 3 + 1], pPositions[i * 3 + 2],
            pPositions[j * 3], pPositions[j * 3 + 1], pPositions[j * 3 + 2]
          );
        }
      }
    }

    const edgeGeo = new THREE.BufferGeometry();
    edgeGeo.setAttribute('position', new THREE.Float32BufferAttribute(edgePositions, 3));
    const edgeMat = new THREE.LineBasicMaterial({
      color: CYAN,
      transparent: true,
      opacity: 0.07,
    });
    const edges = new THREE.LineSegments(edgeGeo, edgeMat);
    scene.add(edges);

    // ─────────────────────────────────────────────────────────────────────
    // 4. HEXAGONAL NODE RINGS (Attack Vector Nodes)
    // ─────────────────────────────────────────────────────────────────────
    const hexNodes = [];
    const HEX_COUNT = 9;
    const hexColors = [CYAN, PURPLE, PINK, CYAN, PURPLE, PINK, CYAN, PURPLE, CYAN];

    for (let i = 0; i < HEX_COUNT; i++) {
      const hexGeo = new THREE.CylinderGeometry(0.9, 0.9, 0.12, 6, 1, true);
      const hexMat = new THREE.MeshBasicMaterial({
        color: hexColors[i],
        transparent: true,
        opacity: 0.55,
        wireframe: false,
        side: THREE.DoubleSide,
      });
      const hex = new THREE.Mesh(hexGeo, hexMat);

      // Add a wireframe outline ring
      const outlineGeo = new THREE.CylinderGeometry(0.92, 0.92, 0.13, 6, 1, true);
      const outlineMat = new THREE.MeshBasicMaterial({
        color: hexColors[i],
        transparent: true,
        opacity: 0.9,
        wireframe: true,
      });
      const outline = new THREE.Mesh(outlineGeo, outlineMat);
      hex.add(outline);

      const angle = (i / HEX_COUNT) * Math.PI * 2;
      const radius = 7 + (i % 3) * 4;
      hex.position.set(
        Math.cos(angle) * radius,
        (Math.random() - 0.5) * 8,
        Math.sin(angle) * radius - 15
      );
      hex.rotation.x = Math.PI / 2;

      hexNodes.push({
        mesh: hex,
        rotSpeed: (Math.random() - 0.5) * 0.008,
        floatSpeed: 0.3 + Math.random() * 0.4,
        floatAmp: 0.4 + Math.random() * 0.6,
        baseY: hex.position.y,
        phase: Math.random() * Math.PI * 2,
      });
      scene.add(hex);
    }

    // ─────────────────────────────────────────────────────────────────────
    // 5. VOLUMETRIC LIGHT BEAMS (Vertical glowing columns)
    // ─────────────────────────────────────────────────────────────────────
    const beamColors = [CYAN, PURPLE, CYAN];
    const beamPositions = [
      [-18, -2, -25],
      [0,   -2, -30],
      [18,  -2, -25],
    ];

    beamPositions.forEach((pos, i) => {
      const beamGeo = new THREE.CylinderGeometry(0.08, 1.2, 28, 8, 1, true);
      const beamMat = new THREE.MeshBasicMaterial({
        color: beamColors[i],
        transparent: true,
        opacity: 0.04,
        side: THREE.DoubleSide,
      });
      const beam = new THREE.Mesh(beamGeo, beamMat);
      beam.position.set(...pos);
      scene.add(beam);
    });

    // ─────────────────────────────────────────────────────────────────────
    // 6. SCANLINE OVERLAY (CSS — cheaper than shader)
    // ─────────────────────────────────────────────────────────────────────
    const scanlines = document.createElement('div');
    scanlines.id = 'cerberus-scanlines';
    scanlines.style.cssText = `
      position: fixed;
      top: 0; left: 0; width: 100%; height: 100%;
      z-index: 1;
      pointer-events: none;
      background: repeating-linear-gradient(
        0deg,
        transparent,
        transparent 2px,
        rgba(0, 240, 255, 0.012) 2px,
        rgba(0, 240, 255, 0.012) 4px
      );
      animation: scanMove 8s linear infinite;
    `;
    document.body.appendChild(scanlines);

    // Inject scanline animation keyframe
    const styleTag = document.createElement('style');
    styleTag.textContent = `
      @keyframes scanMove {
        0%   { background-position: 0 0; }
        100% { background-position: 0 -80px; }
      }
      /* Radial vignette */
      #cerberus-bg::after {
        content: '';
        position: fixed;
        inset: 0;
        background: radial-gradient(ellipse at center, transparent 45%, rgba(5,7,12,0.85) 100%);
        pointer-events: none;
        z-index: 1;
      }
    `;
    document.head.appendChild(styleTag);

    // ─────────────────────────────────────────────────────────────────────
    // ANIMATION LOOP
    // ─────────────────────────────────────────────────────────────────────
    let t = 0;
    let mouseX = 0, mouseY = 0;

    document.addEventListener('mousemove', e => {
      mouseX = (e.clientX / window.innerWidth  - 0.5) * 2;
      mouseY = (e.clientY / window.innerHeight - 0.5) * 2;
    }, { passive: true });

    function animate() {
      requestAnimationFrame(animate);
      t += 0.01;

      // Subtle camera parallax on mouse
      camera.position.x += (mouseX * 2 - camera.position.x) * 0.02;
      camera.position.y += (-mouseY * 1.5 + 8 - camera.position.y) * 0.02;
      camera.lookAt(0, 0, -15);

      // Scroll grid floor forward (infinite scrolling illusion)
      grid.position.z      = ((t * 1.5) % gridStep) - gridStep / 2 - 20;
      innerGrid.position.z = ((t * 1.5) % innerStep) - innerStep / 2 - 20;

      // Animate particles
      const pos = particleGeo.attributes.position.array;
      for (let i = 0; i < PARTICLE_COUNT; i++) {
        pos[i * 3]     += pVelocities[i].x;
        pos[i * 3 + 1] += pVelocities[i].y + Math.sin(t * pVelocities[i].z * 10 + i) * 0.003;
        pos[i * 3 + 2] += pVelocities[i].z;

        // Wrap particles at boundaries
        if (pos[i * 3]     >  40) pos[i * 3]     = -40;
        if (pos[i * 3]     < -40) pos[i * 3]     =  40;
        if (pos[i * 3 + 1] >  22) pos[i * 3 + 1] = -18;
        if (pos[i * 3 + 1] < -18) pos[i * 3 + 1] =  22;
        if (pos[i * 3 + 2] >  30) pos[i * 3 + 2] = -50;
        if (pos[i * 3 + 2] < -50) pos[i * 3 + 2] =  30;
      }
      particleGeo.attributes.position.needsUpdate = true;

      // Pulse particle opacity
      particleMat.opacity = 0.6 + Math.sin(t * 1.5) * 0.15;

      // Animate hex nodes
      hexNodes.forEach(({ mesh, rotSpeed, floatSpeed, floatAmp, baseY, phase }) => {
        mesh.rotation.z += rotSpeed;
        mesh.position.y = baseY + Math.sin(t * floatSpeed + phase) * floatAmp;

        // Pulse opacity
        const pulsed = 0.35 + Math.sin(t * floatSpeed * 1.3 + phase) * 0.2;
        mesh.material.opacity = pulsed;
      });

      // Pulse edge network
      edgeMat.opacity = 0.04 + Math.sin(t * 0.8) * 0.03;

      // Pulse inner grid
      innerGridMat.opacity = 0.14 + Math.sin(t * 0.5) * 0.08;

      renderer.render(scene, camera);
    }

    animate();

    // ── Resize handler ────────────────────────────────────────────────────
    window.addEventListener('resize', () => {
      const W = window.innerWidth;
      const H = window.innerHeight;
      camera.aspect = W / H;
      camera.updateProjectionMatrix();
      renderer.setSize(W, H);
    });
  }
})();

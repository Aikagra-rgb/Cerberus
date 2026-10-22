import React, { useEffect, useRef } from "react";
import * as THREE from "three";

export const Background3D: React.FC = () => {
  const containerRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const container = containerRef.current;
    if (!container) return;

    const canvas = document.createElement("canvas");
    canvas.style.cssText = "width:100%;height:100%;display:block;";
    container.appendChild(canvas);

    let W = window.innerWidth;
    let H = window.innerHeight;

    const renderer = new THREE.WebGLRenderer({ canvas, antialias: true, alpha: true });
    renderer.setSize(W, H);
    renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
    renderer.setClearColor(0x04070f, 1);

    const scene = new THREE.Scene();
    const camera = new THREE.PerspectiveCamera(60, W / H, 0.1, 2000);
    camera.position.set(0, 8, 18);
    camera.lookAt(0, 0, -10);

    scene.fog = new THREE.FogExp2(0x04070f, 0.022);

    const CYAN = 0x06b6d4;
    const PURPLE = 0x8b5cf6;
    const PINK = 0xf43f5e;

    // 1. Perspective grid floor
    const gridSize = 120;
    const gridStep = 4;
    const gridPoints: number[] = [];

    for (let z = -gridSize / 2; z <= gridSize / 2; z += gridStep) {
      gridPoints.push(-gridSize / 2, 0, z, gridSize / 2, 0, z);
    }
    for (let x = -gridSize / 2; x <= gridSize / 2; x += gridStep) {
      gridPoints.push(x, 0, -gridSize / 2, x, 0, gridSize / 2);
    }

    const gridGeo = new THREE.BufferGeometry();
    gridGeo.setAttribute("position", new THREE.Float32BufferAttribute(gridPoints, 3));
    const gridMat = new THREE.LineBasicMaterial({
      color: CYAN,
      transparent: true,
      opacity: 0.07,
    });
    const grid = new THREE.LineSegments(gridGeo, gridMat);
    grid.position.y = -4;
    grid.position.z = -20;
    scene.add(grid);

    const innerGridPoints: number[] = [];
    const innerStep = gridStep * 4;
    for (let z = -gridSize / 2; z <= gridSize / 2; z += innerStep) {
      innerGridPoints.push(-gridSize / 2, 0, z, gridSize / 2, 0, z);
    }
    for (let x = -gridSize / 2; x <= gridSize / 2; x += innerStep) {
      innerGridPoints.push(x, 0, -gridSize / 2, x, 0, gridSize / 2);
    }
    const innerGridGeo = new THREE.BufferGeometry();
    innerGridGeo.setAttribute("position", new THREE.Float32BufferAttribute(innerGridPoints, 3));
    const innerGridMat = new THREE.LineBasicMaterial({
      color: CYAN,
      transparent: true,
      opacity: 0.18,
    });
    const innerGrid = new THREE.LineSegments(innerGridGeo, innerGridMat);
    innerGrid.position.y = -4;
    innerGrid.position.z = -20;
    scene.add(innerGrid);

    // 2. Floating threat particles
    const PARTICLE_COUNT = 220;
    const pPositions = new Float32Array(PARTICLE_COUNT * 3);
    const pVelocities: Array<{ x: number; y: number; z: number }> = [];
    const pColors = new Float32Array(PARTICLE_COUNT * 3);

    const colorOptions = [
      new THREE.Color(CYAN),
      new THREE.Color(PURPLE),
      new THREE.Color(PINK),
    ];

    for (let i = 0; i < PARTICLE_COUNT; i++) {
      pPositions[i * 3] = (Math.random() - 0.5) * 80;
      pPositions[i * 3 + 1] = (Math.random() - 0.5) * 40 + 2;
      pPositions[i * 3 + 2] = (Math.random() - 0.5) * 80 - 10;

      pVelocities.push({
        x: (Math.random() - 0.5) * 0.007,
        y: (Math.random() - 0.5) * 0.005,
        z: (Math.random() - 0.5) * 0.006,
      });

      const col = colorOptions[Math.floor(Math.random() * colorOptions.length)];
      pColors[i * 3] = col.r;
      pColors[i * 3 + 1] = col.g;
      pColors[i * 3 + 2] = col.b;
    }

    const particleGeo = new THREE.BufferGeometry();
    particleGeo.setAttribute("position", new THREE.BufferAttribute(pPositions, 3));
    particleGeo.setAttribute("color", new THREE.BufferAttribute(pColors, 3));

    const particleMat = new THREE.PointsMaterial({
      size: 0.22,
      vertexColors: true,
      transparent: true,
      opacity: 0.65,
      sizeAttenuation: true,
    });

    const particles = new THREE.Points(particleGeo, particleMat);
    scene.add(particles);

    // 3. Neural network edges
    const MAX_EDGE_DIST = 12;
    const edgePositions: number[] = [];
    for (let i = 0; i < PARTICLE_COUNT; i++) {
      for (let j = i + 1; j < PARTICLE_COUNT; j++) {
        const dx = pPositions[i * 3] - pPositions[j * 3];
        const dy = pPositions[i * 3 + 1] - pPositions[j * 3 + 1];
        const dz = pPositions[i * 3 + 2] - pPositions[j * 3 + 2];
        const dist = Math.sqrt(dx * dx + dy * dy + dz * dz);
        if (dist < MAX_EDGE_DIST) {
          edgePositions.push(
            pPositions[i * 3],
            pPositions[i * 3 + 1],
            pPositions[i * 3 + 2],
            pPositions[j * 3],
            pPositions[j * 3 + 1],
            pPositions[j * 3 + 2]
          );
        }
      }
    }

    const edgeGeo = new THREE.BufferGeometry();
    edgeGeo.setAttribute("position", new THREE.Float32BufferAttribute(edgePositions, 3));
    const edgeMat = new THREE.LineBasicMaterial({
      color: CYAN,
      transparent: true,
      opacity: 0.05,
    });
    const edges = new THREE.LineSegments(edgeGeo, edgeMat);
    scene.add(edges);

    // Animation loop
    let animId = 0;
    let t = 0;
    let mouseX = 0;
    let mouseY = 0;

    const handleMouseMove = (e: MouseEvent) => {
      mouseX = (e.clientX / window.innerWidth - 0.5) * 2;
      mouseY = (e.clientY / window.innerHeight - 0.5) * 2;
    };
    window.addEventListener("mousemove", handleMouseMove, { passive: true });

    const animate = () => {
      animId = requestAnimationFrame(animate);
      t += 0.01;

      camera.position.x += (mouseX * 1.6 - camera.position.x) * 0.02;
      camera.position.y += (-mouseY * 1.2 + 8 - camera.position.y) * 0.02;
      camera.lookAt(0, 0, -15);

      grid.position.z = ((t * 1.4) % gridStep) - gridStep / 2 - 20;
      innerGrid.position.z = ((t * 1.4) % innerStep) - innerStep / 2 - 20;

      const pos = particleGeo.attributes.position.array as Float32Array;
      for (let i = 0; i < PARTICLE_COUNT; i++) {
        pos[i * 3] += pVelocities[i].x;
        pos[i * 3 + 1] += pVelocities[i].y + Math.sin(t * pVelocities[i].z * 10 + i) * 0.002;
        pos[i * 3 + 2] += pVelocities[i].z;

        if (pos[i * 3] > 40) pos[i * 3] = -40;
        if (pos[i * 3] < -40) pos[i * 3] = 40;
        if (pos[i * 3 + 1] > 22) pos[i * 3 + 1] = -18;
        if (pos[i * 3 + 1] < -18) pos[i * 3 + 1] = 22;
        if (pos[i * 3 + 2] > 30) pos[i * 3 + 2] = -50;
        if (pos[i * 3 + 2] < -50) pos[i * 3 + 2] = 30;
      }
      particleGeo.attributes.position.needsUpdate = true;

      particleMat.opacity = 0.5 + Math.sin(t * 1.4) * 0.15;
      edgeMat.opacity = 0.035 + Math.sin(t * 0.8) * 0.02;
      innerGridMat.opacity = 0.12 + Math.sin(t * 0.5) * 0.06;

      renderer.render(scene, camera);
    };

    animate();

    const handleResize = () => {
      W = window.innerWidth;
      H = window.innerHeight;
      camera.aspect = W / H;
      camera.updateProjectionMatrix();
      renderer.setSize(W, H);
    };
    window.addEventListener("resize", handleResize);

    return () => {
      cancelAnimationFrame(animId);
      window.removeEventListener("mousemove", handleMouseMove);
      window.removeEventListener("resize", handleResize);
      renderer.dispose();
      if (canvas.parentNode) canvas.parentNode.removeChild(canvas);
    };
  }, []);

  return <div ref={containerRef} className="bg3d-layer" aria-hidden="true" />;
};

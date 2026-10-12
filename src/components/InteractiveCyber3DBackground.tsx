/**
 * MAS-CSI Interactive 3D Cyber Background (Three.js)
 * Live spatial particle constellation, defense shield grid, and threat-reactive matrix.
 * Reacts to mouse cursor motion and system threat state.
 */

import React, { useEffect, useRef } from 'react';
import * as THREE from 'three';
import { store } from '../services/store';

interface Cyber3DBackgroundProps {
  threatLevel: 'NORMAL' | 'SUSPICIOUS' | 'CONFIRMED' | 'CRITICAL';
}

export const InteractiveCyber3DBackground: React.FC<Cyber3DBackgroundProps> = ({ threatLevel }) => {
  const mountRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const mount = mountRef.current;
    if (!mount) return;

    const width = mount.clientWidth || window.innerWidth;
    const height = mount.clientHeight || window.innerHeight;

    // Scene, Camera, Renderer
    const scene = new THREE.Scene();
    const camera = new THREE.PerspectiveCamera(60, width / height, 0.1, 1000);
    camera.position.z = 25;

    const renderer = new THREE.WebGLRenderer({ antialias: true, alpha: true });
    renderer.setSize(width, height);
    renderer.setPixelRatio(Math.min(window.devicePixelRatio, 1.5));
    mount.appendChild(renderer.domElement);

    // Color palette based on threat level
    let primaryHex = 0x06b6d4; // cyan
    let secondaryHex = 0x3b82f6; // blue
    if (threatLevel === 'SUSPICIOUS') {
      primaryHex = 0xf59e0b; // amber
      secondaryHex = 0xd97706;
    } else if (threatLevel === 'CONFIRMED' || threatLevel === 'CRITICAL') {
      primaryHex = 0xf43f5e; // rose/crimson
      secondaryHex = 0xbe123c;
    }

    // 1. Particle Constellation Grid (Nodes)
    const particleCount = 140;
    const particlePositions = new Float32Array(particleCount * 3);
    const particleVelocities: { x: number; y: number; z: number }[] = [];

    for (let i = 0; i < particleCount; i++) {
      particlePositions[i * 3] = (Math.random() - 0.5) * 45;
      particlePositions[i * 3 + 1] = (Math.random() - 0.5) * 35;
      particlePositions[i * 3 + 2] = (Math.random() - 0.5) * 25;
      particleVelocities.push({
        x: (Math.random() - 0.5) * 0.04,
        y: (Math.random() - 0.5) * 0.04,
        z: (Math.random() - 0.5) * 0.04,
      });
    }

    const particleGeometry = new THREE.BufferGeometry();
    particleGeometry.setAttribute('position', new THREE.BufferAttribute(particlePositions, 3));

    const particleMaterial = new THREE.PointsMaterial({
      color: primaryHex,
      size: 0.28,
      transparent: true,
      opacity: 0.65,
    });
    const particleSystem = new THREE.Points(particleGeometry, particleMaterial);
    scene.add(particleSystem);

    // 2. Lines connecting close nodes (Mesh lattice)
    const maxLines = 180;
    const linePositions = new Float32Array(maxLines * 6);
    const lineGeometry = new THREE.BufferGeometry();
    lineGeometry.setAttribute('position', new THREE.BufferAttribute(linePositions, 3));

    const lineMaterial = new THREE.LineBasicMaterial({
      color: secondaryHex,
      transparent: true,
      opacity: 0.18,
    });
    const lineMesh = new THREE.LineSegments(lineGeometry, lineMaterial);
    scene.add(lineMesh);

    // 3. Cyber Perimeter Wave Grid (Bottom plane)
    const gridHelper = new THREE.GridHelper(50, 40, primaryHex, 0x1e293b);
    gridHelper.position.y = -12;
    gridHelper.position.z = -5;
    scene.add(gridHelper);

    // Mouse interaction parallax
    let mouseX = 0;
    let mouseY = 0;
    const handleMouseMove = (e: MouseEvent) => {
      mouseX = (e.clientX / window.innerWidth - 0.5) * 2;
      mouseY = -(e.clientY / window.innerHeight - 0.5) * 2;
    };
    window.addEventListener('mousemove', handleMouseMove);

    // Animation Loop
    let animId: number;
    let clock = new THREE.Clock();

    const animate = () => {
      animId = requestAnimationFrame(animate);
      const delta = clock.getDelta();

      // Parallax smooth camera glide
      camera.position.x += (mouseX * 4 - camera.position.x) * 0.03;
      camera.position.y += (mouseY * 3 - camera.position.y) * 0.03;
      camera.lookAt(0, 0, 0);

      // Move particles
      const positions = particleGeometry.attributes.position.array as Float32Array;
      for (let i = 0; i < particleCount; i++) {
        positions[i * 3] += particleVelocities[i].x;
        positions[i * 3 + 1] += particleVelocities[i].y;
        positions[i * 3 + 2] += particleVelocities[i].z;

        // Boundary wrap
        if (Math.abs(positions[i * 3]) > 25) positions[i * 3] *= -0.95;
        if (Math.abs(positions[i * 3 + 1]) > 20) positions[i * 3 + 1] *= -0.95;
        if (Math.abs(positions[i * 3 + 2]) > 15) positions[i * 3 + 2] *= -0.95;
      }
      particleGeometry.attributes.position.needsUpdate = true;

      // Update connecting line edges
      let lineIndex = 0;
      for (let i = 0; i < particleCount && lineIndex < maxLines; i++) {
        for (let j = i + 1; j < particleCount && lineIndex < maxLines; j++) {
          const dx = positions[i * 3] - positions[j * 3];
          const dy = positions[i * 3 + 1] - positions[j * 3 + 1];
          const dz = positions[i * 3 + 2] - positions[j * 3 + 2];
          const distSq = dx * dx + dy * dy + dz * dz;

          if (distSq < 36) { // Distance < 6 units
            linePositions[lineIndex * 6] = positions[i * 3];
            linePositions[lineIndex * 6 + 1] = positions[i * 3 + 1];
            linePositions[lineIndex * 6 + 2] = positions[i * 3 + 2];
            linePositions[lineIndex * 6 + 3] = positions[j * 3];
            linePositions[lineIndex * 6 + 4] = positions[j * 3 + 1];
            linePositions[lineIndex * 6 + 5] = positions[j * 3 + 2];
            lineIndex++;
          }
        }
      }
      lineGeometry.attributes.position.needsUpdate = true;

      // Grid subtle rotation & wave
      gridHelper.position.z = -5 + Math.sin(clock.getElapsedTime() * 0.5) * 1.5;

      renderer.render(scene, camera);
    };

    animate();

    const handleResize = () => {
      if (!mount) return;
      const w = mount.clientWidth || window.innerWidth;
      const h = mount.clientHeight || window.innerHeight;
      camera.aspect = w / h;
      camera.updateProjectionMatrix();
      renderer.setSize(w, h);
    };
    window.addEventListener('resize', handleResize);

    return () => {
      window.removeEventListener('mousemove', handleMouseMove);
      window.removeEventListener('resize', handleResize);
      cancelAnimationFrame(animId);
      if (mount && renderer.domElement) {
        mount.removeChild(renderer.domElement);
      }
      particleGeometry.dispose();
      particleMaterial.dispose();
      lineGeometry.dispose();
      lineMaterial.dispose();
      gridHelper.dispose();
      renderer.dispose();
    };
  }, [threatLevel]);

  return (
    <div
      ref={mountRef}
      className="fixed inset-0 pointer-events-none z-0 opacity-40 transition-opacity duration-700 overflow-hidden"
      style={{ willChange: 'transform' }}
    />
  );
};

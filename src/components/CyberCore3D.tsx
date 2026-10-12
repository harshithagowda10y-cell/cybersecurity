/**
 * 3D Interactive Cyber Core & Threat Sphere Visualization (Three.js)
 * Full interactive 3D with mouse drag rotation, zoom, multiple visual models:
 * 1. Icosahedral Quantum Core
 * 2. Hexagonal Defense Shield
 * 3. Spatial Threat Lattice
 * Note: High-fidelity visualization for SOC operator situational awareness.
 */

import React, { useEffect, useRef, useState } from 'react';
import * as THREE from 'three';
import { Rotate3D, Layers, Shield, Sparkles, ZoomIn, ZoomOut } from 'lucide-react';

interface CyberCore3DProps {
  threatLevel: 'NORMAL' | 'SUSPICIOUS' | 'CONFIRMED' | 'CRITICAL';
  eventsCount: number;
}

export const CyberCore3D: React.FC<CyberCore3DProps> = ({ threatLevel, eventsCount }) => {
  const mountRef = useRef<HTMLDivElement>(null);
  const [modelMode, setModelMode] = useState<'core' | 'shield' | 'lattice'>('core');
  const [isDragging, setIsDragging] = useState(false);

  useEffect(() => {
    const mount = mountRef.current;
    if (!mount) return;

    // Clean previous children if any
    while (mount.firstChild) {
      mount.removeChild(mount.firstChild);
    }

    const width = mount.clientWidth || 360;
    const height = mount.clientHeight || 280;

    // Scene setup
    const scene = new THREE.Scene();
    const camera = new THREE.PerspectiveCamera(50, width / height, 0.1, 1000);
    camera.position.z = 4.3;

    const renderer = new THREE.WebGLRenderer({ antialias: true, alpha: true });
    renderer.setSize(width, height);
    renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
    mount.appendChild(renderer.domElement);

    // Color based on threat level
    let primaryColorHex = 0x06b6d4; // cyan
    let secondaryColorHex = 0x3b82f6; // blue
    if (threatLevel === 'SUSPICIOUS') {
      primaryColorHex = 0xf59e0b; // amber
      secondaryColorHex = 0xd97706;
    } else if (threatLevel === 'CONFIRMED') {
      primaryColorHex = 0xf43f5e; // rose
      secondaryColorHex = 0xe11d48;
    } else if (threatLevel === 'CRITICAL') {
      primaryColorHex = 0xef4444; // crimson
      secondaryColorHex = 0x991b1b;
    }

    const mainGroup = new THREE.Group();
    scene.add(mainGroup);

    // 1. Core mesh
    let coreGeo: THREE.BufferGeometry;
    if (modelMode === 'core') {
      coreGeo = new THREE.IcosahedronGeometry(1.2, 1);
    } else if (modelMode === 'shield') {
      coreGeo = new THREE.DodecahedronGeometry(1.3, 0);
    } else {
      coreGeo = new THREE.OctahedronGeometry(1.3, 2);
    }

    const coreMat = new THREE.MeshBasicMaterial({
      color: primaryColorHex,
      wireframe: true,
      transparent: true,
      opacity: 0.85,
    });
    const coreMesh = new THREE.Mesh(coreGeo, coreMat);
    mainGroup.add(coreMesh);

    // Inner glowing sphere
    const innerGeo = new THREE.SphereGeometry(0.7, 16, 16);
    const innerMat = new THREE.MeshBasicMaterial({
      color: secondaryColorHex,
      wireframe: false,
      transparent: true,
      opacity: 0.25,
    });
    const innerMesh = new THREE.Mesh(innerGeo, innerMat);
    mainGroup.add(innerMesh);

    // Outer shield rings
    const ringGeo = new THREE.TorusGeometry(1.9, 0.025, 16, 80);
    const ringMat = new THREE.MeshBasicMaterial({
      color: primaryColorHex,
      wireframe: true,
      transparent: true,
      opacity: 0.6,
    });
    const ringMesh = new THREE.Mesh(ringGeo, ringMat);
    mainGroup.add(ringMesh);

    const ringGeo2 = new THREE.TorusGeometry(2.1, 0.018, 16, 80);
    const ringMat2 = new THREE.MeshBasicMaterial({
      color: secondaryColorHex,
      transparent: true,
      opacity: 0.45,
    });
    const ringMesh2 = new THREE.Mesh(ringGeo2, ringMat2);
    ringMesh2.rotation.x = Math.PI / 3;
    ringMesh2.rotation.y = Math.PI / 4;
    mainGroup.add(ringMesh2);

    // Orbiting telemetry particles
    const particleCount = 140;
    const particlePositions = new Float32Array(particleCount * 3);
    for (let i = 0; i < particleCount * 3; i += 3) {
      const r = 2.1 + Math.random() * 0.9;
      const theta = Math.random() * Math.PI * 2;
      const phi = Math.acos(2 * Math.random() - 1);
      particlePositions[i] = r * Math.sin(phi) * Math.cos(theta);
      particlePositions[i + 1] = r * Math.sin(phi) * Math.sin(theta);
      particlePositions[i + 2] = r * Math.cos(phi);
    }
    const particleGeo = new THREE.BufferGeometry();
    particleGeo.setAttribute('position', new THREE.BufferAttribute(particlePositions, 3));
    const particleMat = new THREE.PointsMaterial({
      size: 0.045,
      color: primaryColorHex,
      transparent: true,
      opacity: 0.85,
    });
    const particles = new THREE.Points(particleGeo, particleMat);
    mainGroup.add(particles);

    // Mouse drag interaction
    let isMouseDown = false;
    let prevMouseX = 0;
    let prevMouseY = 0;

    const handleMouseDown = (e: MouseEvent) => {
      isMouseDown = true;
      setIsDragging(true);
      prevMouseX = e.clientX;
      prevMouseY = e.clientY;
    };

    const handleMouseMove = (e: MouseEvent) => {
      if (!isMouseDown) return;
      const deltaX = e.clientX - prevMouseX;
      const deltaY = e.clientY - prevMouseY;
      mainGroup.rotation.y += deltaX * 0.01;
      mainGroup.rotation.x += deltaY * 0.01;
      prevMouseX = e.clientX;
      prevMouseY = e.clientY;
    };

    const handleMouseUp = () => {
      isMouseDown = false;
      setIsDragging(false);
    };

    const handleWheel = (e: WheelEvent) => {
      e.preventDefault();
      camera.position.z = Math.min(Math.max(camera.position.z + e.deltaY * 0.005, 2.5), 7.0);
    };

    mount.addEventListener('mousedown', handleMouseDown);
    window.addEventListener('mousemove', handleMouseMove);
    window.addEventListener('mouseup', handleMouseUp);
    mount.addEventListener('wheel', handleWheel, { passive: false });

    // Animation loop
    let reqId: number;
    let clock = new THREE.Clock();

    const animate = () => {
      reqId = requestAnimationFrame(animate);
      const delta = clock.getDelta();

      if (!isMouseDown) {
        const speed = threatLevel === 'CRITICAL' ? 1.6 : threatLevel === 'CONFIRMED' ? 1.2 : 0.6;
        mainGroup.rotation.y += delta * speed * 0.5;
        ringMesh.rotation.z += delta * speed * 0.7;
        ringMesh2.rotation.y -= delta * speed * 0.6;
        particles.rotation.y += delta * 0.2;
      }

      // Gentle pulsing effect
      const time = clock.getElapsedTime();
      const pulse = 1 + Math.sin(time * 3) * 0.04;
      coreMesh.scale.set(pulse, pulse, pulse);

      renderer.render(scene, camera);
    };

    animate();

    const handleResize = () => {
      if (!mount) return;
      const newWidth = mount.clientWidth;
      const newHeight = mount.clientHeight;
      camera.aspect = newWidth / newHeight;
      camera.updateProjectionMatrix();
      renderer.setSize(newWidth, newHeight);
    };
    window.addEventListener('resize', handleResize);

    return () => {
      cancelAnimationFrame(reqId);
      window.removeEventListener('resize', handleResize);
      mount.removeEventListener('mousedown', handleMouseDown);
      window.removeEventListener('mousemove', handleMouseMove);
      window.removeEventListener('mouseup', handleMouseUp);
      mount.removeEventListener('wheel', handleWheel);
      if (mount.contains(renderer.domElement)) {
        mount.removeChild(renderer.domElement);
      }
      renderer.dispose();
      coreGeo.dispose();
      coreMat.dispose();
      ringGeo.dispose();
      ringMat.dispose();
      particleGeo.dispose();
      particleMat.dispose();
    };
  }, [threatLevel, modelMode]);

  return (
    <div className="relative w-full h-full group font-mono text-xs">
      <div
        ref={mountRef}
        className={`w-full h-full cursor-grab ${isDragging ? 'cursor-grabbing' : ''}`}
        title="Click & drag to rotate 3D cyber model. Scroll wheel to zoom."
      />

      {/* Model Mode Switcher in top right */}
      <div className="absolute top-2 right-2 flex bg-slate-950/80 backdrop-blur-xs border border-slate-800 rounded p-0.5 gap-1 shadow-md">
        <button
          onClick={() => setModelMode('core')}
          className={`px-2 py-0.5 rounded text-[10px] font-bold cursor-pointer transition ${
            modelMode === 'core'
              ? 'bg-cyan-950 text-cyan-300 border border-cyan-800'
              : 'text-slate-400 hover:text-slate-200'
          }`}
          title="Quantum Icosahedral Core"
        >
          Core
        </button>
        <button
          onClick={() => setModelMode('shield')}
          className={`px-2 py-0.5 rounded text-[10px] font-bold cursor-pointer transition ${
            modelMode === 'shield'
              ? 'bg-cyan-950 text-cyan-300 border border-cyan-800'
              : 'text-slate-400 hover:text-slate-200'
          }`}
          title="Hexagonal Defense Shield"
        >
          Shield
        </button>
        <button
          onClick={() => setModelMode('lattice')}
          className={`px-2 py-0.5 rounded text-[10px] font-bold cursor-pointer transition ${
            modelMode === 'lattice'
              ? 'bg-cyan-950 text-cyan-300 border border-cyan-800'
              : 'text-slate-400 hover:text-slate-200'
          }`}
          title="Spatial Threat Lattice"
        >
          Lattice
        </button>
      </div>

      {/* Interactive Helper Overlay in bottom left */}
      <div className="absolute bottom-2 left-2 text-[10px] text-slate-500 bg-slate-950/70 backdrop-blur-xs px-2 py-1 rounded border border-slate-800 flex items-center gap-1.5 pointer-events-none">
        <Rotate3D className="w-3 h-3 text-cyan-400" />
        <span>360° Drag to Rotate · Scroll to Zoom</span>
      </div>
    </div>
  );
};

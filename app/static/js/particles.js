/**
 * PHISHGUARD NEXUS — Particle Network Background
 * Animated connecting particle field for the premium dashboard.
 */
(function() {
  'use strict';

  const canvas = document.getElementById('particle-canvas');
  if (!canvas) return;

  const ctx = canvas.getContext('2d');
  let particles = [];
  let mouse = { x: -1000, y: -1000 };
  let animId = null;

  const CONFIG = {
    count: 80,
    maxDist: 150,
    speed: 0.3,
    particleColor: '148, 163, 184',
    lineColor: '148, 163, 184',
    lineOpacity: 0.08,
    radius: 1.5,
  };

  function resize() {
    canvas.width = window.innerWidth;
    canvas.height = window.innerHeight;
  }

  class Particle {
    constructor() {
      this.x = Math.random() * canvas.width;
      this.y = Math.random() * canvas.height;
      const angle = Math.random() * 2 * Math.PI;
      this.vx = Math.cos(angle) * CONFIG.speed;
      this.vy = Math.sin(angle) * CONFIG.speed;
      this.r = CONFIG.radius * (0.5 + Math.random() * 0.5);
    }

    update() {
      this.x += this.vx;
      this.y += this.vy;
      if (this.x < 0 || this.x > canvas.width) this.vx *= -1;
      if (this.y < 0 || this.y > canvas.height) this.vy *= -1;
    }

    draw() {
      ctx.beginPath();
      ctx.arc(this.x, this.y, this.r, 0, Math.PI * 2);
      ctx.fillStyle = `rgba(${CONFIG.particleColor}, 0.4)`;
      ctx.fill();
    }
  }

  function init() {
    resize();
    particles = [];
    for (let i = 0; i < CONFIG.count; i++) {
      particles.push(new Particle());
    }
  }

  function drawLines() {
    for (let i = 0; i < particles.length; i++) {
      for (let j = i + 1; j < particles.length; j++) {
        const dx = particles[i].x - particles[j].x;
        const dy = particles[i].y - particles[j].y;
        const dist = Math.sqrt(dx * dx + dy * dy);
        if (dist < CONFIG.maxDist) {
          const opacity = CONFIG.lineOpacity * (1 - dist / CONFIG.maxDist);
          ctx.beginPath();
          ctx.moveTo(particles[i].x, particles[i].y);
          ctx.lineTo(particles[j].x, particles[j].y);
          ctx.strokeStyle = `rgba(${CONFIG.lineColor}, ${opacity})`;
          ctx.lineWidth = 0.6;
          ctx.stroke();
        }
      }
    }
    // Mouse connections
    if (mouse.x > 0 && mouse.y > 0) {
      for (const p of particles) {
        const dx = mouse.x - p.x;
        const dy = mouse.y - p.y;
        const dist = Math.sqrt(dx * dx + dy * dy);
        if (dist < CONFIG.maxDist * 1.2) {
          const opacity = CONFIG.lineOpacity * 1.5 * (1 - dist / (CONFIG.maxDist * 1.2));
          ctx.beginPath();
          ctx.moveTo(mouse.x, mouse.y);
          ctx.lineTo(p.x, p.y);
          ctx.strokeStyle = `rgba(6, 182, 212, ${opacity})`;
          ctx.lineWidth = 0.8;
          ctx.stroke();
        }
      }
    }
  }

  function animate() {
    ctx.clearRect(0, 0, canvas.width, canvas.height);
    for (const p of particles) {
      p.update();
      p.draw();
    }
    drawLines();
    animId = requestAnimationFrame(animate);
  }

  window.addEventListener('resize', () => {
    resize();
  });

  document.addEventListener('mousemove', (e) => {
    mouse.x = e.clientX;
    mouse.y = e.clientY;
  });

  document.addEventListener('mouseleave', () => {
    mouse.x = -1000;
    mouse.y = -1000;
  });

  init();
  animate();
})();

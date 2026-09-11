/**
 * Phish-Guard - Cyber Defense Animated Background System
 * Lightweight, 60fps, high-performance canvas & ambient particle mesh.
 * Features: Multi-role cyber nodes, active packet telemetry, radar pulse waves,
 * touch-reactive constellation glow, and mobile-optimized glassmorphic integration.
 */
(() => {
    'use strict';

    const canvas = document.getElementById('cyberBackground');
    if (!canvas) return;

    const ctx = canvas.getContext('2d', { alpha: true });
    if (!ctx) return;

    let prefersReducedMotion = false;
    try {
        const mediaQuery = window.matchMedia('(prefers-reduced-motion: reduce)');
        prefersReducedMotion = mediaQuery.matches;
        const updateMotion = (e) => { prefersReducedMotion = e.matches; };
        if (mediaQuery.addEventListener) {
            mediaQuery.addEventListener('change', updateMotion);
        } else if (mediaQuery.addListener) {
            mediaQuery.addListener(updateMotion);
        }
    } catch (e) {
        prefersReducedMotion = false;
    }

    let width = 0;
    let height = 0;
    let dpr = 1;
    let animId = null;
    let isRunning = false;
    let lastTime = 0;

    // Node & Packet Configuration
    let nodes = [];
    let packets = [];
    let pulses = [];
    let mouse = { x: -9999, y: -9999, radius: 140, active: false, intensity: 0 };

    // Colors matching Phish-Guard Cyber Defense Palette
    const COLORS = {
        cyan: { r: 56, g: 189, b: 248 },     // #38bdf8 - Relay
        green: { r: 0, g: 255, b: 156 },     // #00ff9c - Sensor
        indigo: { r: 129, g: 140, b: 248 },  // #818cf8 - Core Hub
        purple: { r: 168, g: 85, b: 247 },   // #a855f7 - Encryption Node
        red: { r: 244, g: 63, b: 94 }        // #f43f5e - Threat Quarantined
    };

    function getNodeCount() {
        const w = window.innerWidth;
        if (w < 480) return 26;
        if (w < 768) return 34;
        if (w < 1200) return 46;
        return 60;
    }

    function getMaxDistance() {
        const w = window.innerWidth;
        if (w < 480) return 130;
        if (w < 768) return 145;
        if (w < 1200) return 160;
        return 175;
    }

    function getMouseRadius() {
        return window.innerWidth < 600 ? 110 : 160;
    }

    class CyberNode {
        constructor(initial = true) {
            this.reset(initial);
        }

        reset(initial = false) {
            const w = width || window.innerWidth || 360;
            const h = height || window.innerHeight || 640;

            this.x = initial ? Math.random() * w : (Math.random() > 0.5 ? 0 : w);
            this.y = initial ? Math.random() * h : Math.random() * h;

            const isMobile = window.innerWidth < 600;
            const speedBase = prefersReducedMotion ? 0.12 : (isMobile ? 0.4 : 0.55);
            const speedVar = prefersReducedMotion ? 0.08 : (isMobile ? 0.35 : 0.5);
            const speed = speedBase + Math.random() * speedVar;
            const angle = Math.random() * Math.PI * 2;

            this.vx = Math.cos(angle) * speed;
            this.vy = Math.sin(angle) * speed;

            const rand = Math.random();
            if (rand < 0.45) {
                this.type = 'relay';
                this.color = COLORS.cyan;
                this.baseRadius = 2.0;
            } else if (rand < 0.75) {
                this.type = 'sensor';
                this.color = COLORS.green;
                this.baseRadius = 2.4;
            } else if (rand < 0.92) {
                this.type = 'hub';
                this.color = COLORS.indigo;
                this.baseRadius = 3.2;
            } else {
                this.type = 'threat';
                this.color = COLORS.purple;
                this.baseRadius = 2.2;
            }

            this.radius = this.baseRadius;
            this.pulse = Math.random() * Math.PI * 2;
            this.pulseSpeed = 0.025 + Math.random() * 0.035;
        }

        update() {
            this.x += this.vx;
            this.y += this.vy;

            if (this.x < 0) { this.x = 0; this.vx = Math.abs(this.vx); }
            else if (this.x > width) { this.x = width; this.vx = -Math.abs(this.vx); }
            if (this.y < 0) { this.y = 0; this.vy = Math.abs(this.vy); }
            else if (this.y > height) { this.y = height; this.vy = -Math.abs(this.vy); }

            this.pulse += this.pulseSpeed;
            if (this.type === 'sensor' || this.type === 'hub') {
                this.radius = this.baseRadius + Math.sin(this.pulse) * 0.8;
            }

            if (mouse.intensity > 0.01) {
                const dx = mouse.x - this.x;
                const dy = mouse.y - this.y;
                const distSq = dx * dx + dy * dy;
                const rSq = mouse.radius * mouse.radius;

                if (distSq < rSq && distSq > 0) {
                    const dist = Math.sqrt(distSq);
                    const force = (1 - dist / mouse.radius) * 1.6 * mouse.intensity;
                    this.x -= (dx / dist) * force;
                    this.y -= (dy / dist) * force;
                }
            }
        }

        draw(ctx) {
            const { r, g, b } = this.color;

            if (this.type === 'sensor') {
                const ringAlpha = (0.22 + Math.sin(this.pulse) * 0.18);
                if (ringAlpha > 0) {
                    ctx.beginPath();
                    ctx.arc(this.x, this.y, this.radius * 2.6, 0, Math.PI * 2);
                    ctx.strokeStyle = `rgba(${r}, ${g}, ${b}, ${ringAlpha})`;
                    ctx.lineWidth = 0.9;
                    ctx.stroke();
                }
            } else if (this.type === 'hub') {
                const ringAlpha = (0.28 + Math.sin(this.pulse) * 0.22);
                if (ringAlpha > 0) {
                    ctx.beginPath();
                    ctx.arc(this.x, this.y, this.radius * 3.2, 0, Math.PI * 2);
                    ctx.strokeStyle = `rgba(${r}, ${g}, ${b}, ${ringAlpha})`;
                    ctx.lineWidth = 1.1;
                    ctx.stroke();

                    ctx.beginPath();
                    ctx.arc(this.x, this.y, this.radius * 1.8, 0, Math.PI * 2);
                    ctx.strokeStyle = `rgba(${r}, ${g}, ${b}, ${ringAlpha * 0.7})`;
                    ctx.lineWidth = 0.7;
                    ctx.stroke();
                }
            }

            ctx.beginPath();
            ctx.arc(this.x, this.y, this.radius, 0, Math.PI * 2);
            ctx.fillStyle = `rgba(${r}, ${g}, ${b}, 0.92)`;
            ctx.shadowColor = `rgba(${r}, ${g}, ${b}, 0.75)`;
            ctx.shadowBlur = 8;
            ctx.fill();
            ctx.shadowBlur = 0;
        }
    }

    class TelemetryPacket {
        constructor(source, target) {
            this.source = source;
            this.target = target;
            this.progress = 0;
            this.speed = 0.012 + Math.random() * 0.016;
            this.color = source.color;
            this.size = 1.8;
        }

        update() {
            this.progress += this.speed;
            return this.progress < 1;
        }

        draw(ctx) {
            const curX = this.source.x + (this.target.x - this.source.x) * this.progress;
            const curY = this.source.y + (this.target.y - this.source.y) * this.progress;
            const { r, g, b } = this.color;

            ctx.beginPath();
            ctx.arc(curX, curY, this.size, 0, Math.PI * 2);
            ctx.fillStyle = `rgba(${r}, ${g}, ${b}, 0.98)`;
            ctx.shadowColor = `rgba(${r}, ${g}, ${b}, 0.95)`;
            ctx.shadowBlur = 10;
            ctx.fill();
            ctx.shadowBlur = 0;
        }
    }

    class RadarPulse {
        constructor(x, y, color) {
            this.x = x;
            this.y = y;
            this.radius = 4;
            this.maxRadius = Math.max(width, height) * 0.45;
            this.speed = 2.4;
            this.color = color || COLORS.cyan;
            this.alpha = 0.4;
        }

        update() {
            this.radius += this.speed;
            this.alpha = (1 - this.radius / this.maxRadius) * 0.35;
            return this.radius < this.maxRadius && this.alpha > 0.01;
        }

        draw(ctx) {
            const { r, g, b } = this.color;
            ctx.beginPath();
            ctx.arc(this.x, this.y, this.radius, 0, Math.PI * 2);
            ctx.strokeStyle = `rgba(${r}, ${g}, ${b}, ${this.alpha})`;
            ctx.lineWidth = 1.2;
            ctx.stroke();
        }
    }

    function resize() {
        const prevWidth = width;
        const prevHeight = height;

        dpr = Math.min(window.devicePixelRatio || 1, 2);
        const newWidth = window.innerWidth || document.documentElement.clientWidth || 360;
        const newHeight = window.innerHeight || document.documentElement.clientHeight || 640;

        if (width > 0 && Math.abs(newWidth - prevWidth) < 5 && Math.abs(newHeight - prevHeight) < 80) {
            return;
        }

        width = newWidth;
        height = newHeight;
        mouse.radius = getMouseRadius();

        canvas.width = Math.floor(width * dpr);
        canvas.height = Math.floor(height * dpr);

        ctx.setTransform(1, 0, 0, 1, 0, 0);
        ctx.scale(dpr, dpr);

        updateNodesOnResize(prevWidth, prevHeight);
    }

    function updateNodesOnResize(prevWidth, prevHeight) {
        const targetCount = getNodeCount();
        if (nodes.length === 0) {
            initNodes();
            return;
        }

        if (prevWidth > 0 && prevHeight > 0) {
            const scaleX = width / prevWidth;
            const scaleY = height / prevHeight;
            nodes.forEach(n => {
                n.x = Math.max(0, Math.min(width, n.x * scaleX));
                n.y = Math.max(0, Math.min(height, n.y * scaleY));
            });
        }

        while (nodes.length < targetCount) {
            nodes.push(new CyberNode(true));
        }
        if (nodes.length > targetCount) {
            nodes.length = targetCount;
        }
    }

    function initNodes() {
        const count = getNodeCount();
        nodes = [];
        for (let i = 0; i < count; i++) {
            nodes.push(new CyberNode(true));
        }
        packets = [];
        pulses = [];
    }

    function loop(currentTime) {
        if (!isRunning) return;

        if (!mouse.active && mouse.intensity > 0) {
            mouse.intensity -= 0.025;
            if (mouse.intensity < 0) mouse.intensity = 0;
        } else if (mouse.active && mouse.intensity < 1) {
            mouse.intensity = Math.min(1, mouse.intensity + 0.1);
        }

        ctx.clearRect(0, 0, width, height);

        const maxDist = getMaxDistance();
        const maxDistSq = maxDist * maxDist;

        if (!prefersReducedMotion && (!lastTime || currentTime - lastTime > 5500)) {
            lastTime = currentTime;
            const hubNodes = nodes.filter(n => n.type === 'hub' || n.type === 'sensor');
            if (hubNodes.length > 0) {
                const origin = hubNodes[Math.floor(Math.random() * hubNodes.length)];
                if (pulses.length < 3) {
                    pulses.push(new RadarPulse(origin.x, origin.y, origin.color));
                }
            }
        }

        for (let i = pulses.length - 1; i >= 0; i--) {
            const p = pulses[i];
            if (p.update()) {
                p.draw(ctx);
            } else {
                pulses.splice(i, 1);
            }
        }

        for (let i = 0; i < nodes.length; i++) {
            nodes[i].update();
            nodes[i].draw(ctx);
        }

        const maxPackets = window.innerWidth < 600 ? 8 : 14;
        const packetChance = window.innerWidth < 600 ? 0.005 : 0.0035;

        for (let i = 0; i < nodes.length; i++) {
            for (let j = i + 1; j < nodes.length; j++) {
                const n1 = nodes[i];
                const n2 = nodes[j];
                const dx = n2.x - n1.x;
                const dy = n2.y - n1.y;
                const distSq = dx * dx + dy * dy;

                if (distSq < maxDistSq) {
                    const ratio = 1 - distSq / maxDistSq;
                    const alpha = ratio * 0.42;
                    const r = Math.round((n1.color.r + n2.color.r) / 2);
                    const g = Math.round((n1.color.g + n2.color.g) / 2);
                    const b = Math.round((n1.color.b + n2.color.b) / 2);

                    ctx.beginPath();
                    ctx.moveTo(n1.x, n1.y);
                    ctx.lineTo(n2.x, n2.y);
                    ctx.strokeStyle = `rgba(${r}, ${g}, ${b}, ${alpha})`;
                    ctx.lineWidth = ratio > 0.6 ? 1.0 : 0.75;
                    ctx.stroke();

                    if (!prefersReducedMotion && packets.length < maxPackets && Math.random() < packetChance) {
                        packets.push(new TelemetryPacket(n1, n2));
                    }
                }
            }
        }

        if (mouse.intensity > 0.01) {
            const mDistSq = mouse.radius * mouse.radius;
            for (let i = 0; i < nodes.length; i++) {
                const n = nodes[i];
                const dx = mouse.x - n.x;
                const dy = mouse.y - n.y;
                const distSq = dx * dx + dy * dy;

                if (distSq < mDistSq) {
                    const alpha = (1 - distSq / mDistSq) * 0.55 * mouse.intensity;
                    ctx.beginPath();
                    ctx.moveTo(n.x, n.y);
                    ctx.lineTo(mouse.x, mouse.y);
                    ctx.strokeStyle = `rgba(56, 189, 248, ${alpha})`;
                    ctx.lineWidth = 1.1;
                    ctx.stroke();
                }
            }

            ctx.beginPath();
            ctx.arc(mouse.x, mouse.y, 4 + (1 - mouse.intensity) * 12, 0, Math.PI * 2);
            ctx.strokeStyle = `rgba(0, 255, 156, ${0.45 * mouse.intensity})`;
            ctx.lineWidth = 1.5;
            ctx.stroke();
        }

        for (let i = packets.length - 1; i >= 0; i--) {
            const p = packets[i];
            if (p.update()) {
                p.draw(ctx);
            } else {
                packets.splice(i, 1);
            }
        }

        animId = requestAnimationFrame(loop);
    }

    function start() {
        if (isRunning) return;
        isRunning = true;
        animId = requestAnimationFrame(loop);
    }

    function stop() {
        isRunning = false;
        if (animId) {
            cancelAnimationFrame(animId);
            animId = null;
        }
    }

    function init() {
        resize();
        start();

        let resizeTimer;
        window.addEventListener('resize', () => {
            clearTimeout(resizeTimer);
            resizeTimer = setTimeout(() => {
                resize();
            }, 120);
        }, { passive: true });

        window.addEventListener('orientationchange', () => {
            setTimeout(resize, 200);
        }, { passive: true });

        window.addEventListener('mousemove', (e) => {
            mouse.x = e.clientX;
            mouse.y = e.clientY;
            mouse.active = true;
        }, { passive: true });

        window.addEventListener('mouseleave', () => {
            mouse.active = false;
        }, { passive: true });

        window.addEventListener('touchstart', (e) => {
            if (e.touches && e.touches[0]) {
                mouse.x = e.touches[0].clientX;
                mouse.y = e.touches[0].clientY;
                mouse.active = true;
                mouse.intensity = 1.0;
            }
        }, { passive: true });

        window.addEventListener('touchmove', (e) => {
            if (e.touches && e.touches[0]) {
                mouse.x = e.touches[0].clientX;
                mouse.y = e.touches[0].clientY;
                mouse.active = true;
            }
        }, { passive: true });

        window.addEventListener('touchend', () => {
            mouse.active = false;
        }, { passive: true });

        window.addEventListener('touchcancel', () => {
            mouse.active = false;
        }, { passive: true });

        document.addEventListener('visibilitychange', () => {
            if (document.hidden) {
                stop();
            } else {
                start();
            }
        });
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }
})();

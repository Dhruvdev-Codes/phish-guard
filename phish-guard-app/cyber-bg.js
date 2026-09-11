/**
 * Phish-Guard - Cyber Defense Animated Background System
 * Lightweight, 60fps, high-performance canvas & ambient particle mesh.
 */
(() => {
    'use strict';

    const canvas = document.getElementById('cyberBackground');
    if (!canvas) return;

    const ctx = canvas.getContext('2d', { alpha: true });
    if (!ctx) return;

    const prefersReducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)');

    let width = 0;
    let height = 0;
    let dpr = 1;
    let animId = null;
    let isRunning = false;

    // Node & Packet Configuration
    let nodes = [];
    let packets = [];
    let mouse = { x: -9999, y: -9999, radius: 140, active: false };

    // Colors matching Phish-Guard Cyber Palette
    const COLORS = {
        cyan: { r: 56, g: 189, b: 248 },     // #38bdf8
        green: { r: 0, g: 255, b: 156 },     // #00ff9c
        indigo: { r: 99, g: 102, b: 241 },   // #6366f1
        purple: { r: 168, g: 85, b: 247 }    // #a855f7
    };

    function getNodeCount() {
        const w = window.innerWidth;
        if (w < 600) return 20;
        if (w < 1024) return 32;
        return 46;
    }

    function getMaxDistance() {
        return window.innerWidth < 600 ? 110 : 150;
    }

    function getMouseRadius() {
        return window.innerWidth < 600 ? 90 : 140;
    }

    class CyberNode {
        constructor() {
            this.reset(true);
        }

        reset(initial = false) {
            this.x = initial ? Math.random() * width : (Math.random() > 0.5 ? 0 : width);
            this.y = initial ? Math.random() * height : Math.random() * height;
            
            const speed = (0.22 + Math.random() * 0.42) * (window.innerWidth < 600 ? 0.7 : 1);
            const angle = Math.random() * Math.PI * 2;
            this.vx = Math.cos(angle) * speed;
            this.vy = Math.sin(angle) * speed;

            this.baseRadius = 1.6 + Math.random() * 1.6;
            this.radius = this.baseRadius;
            
            const rand = Math.random();
            if (rand < 0.5) {
                this.type = 'relay';
                this.color = COLORS.cyan;
            } else if (rand < 0.8) {
                this.type = 'sensor';
                this.color = COLORS.green;
            } else {
                this.type = 'hub';
                this.color = COLORS.indigo;
            }

            this.pulse = Math.random() * Math.PI * 2;
            this.pulseSpeed = 0.02 + Math.random() * 0.03;
        }

        update() {
            this.x += this.vx;
            this.y += this.vy;

            if (this.x < 0) { this.x = 0; this.vx *= -1; }
            else if (this.x > width) { this.x = width; this.vx *= -1; }
            if (this.y < 0) { this.y = 0; this.vy *= -1; }
            else if (this.y > height) { this.y = height; this.vy *= -1; }

            this.pulse += this.pulseSpeed;
            if (this.type === 'sensor' || this.type === 'hub') {
                this.radius = this.baseRadius + Math.sin(this.pulse) * 0.7;
            }

            if (mouse.active) {
                const dx = mouse.x - this.x;
                const dy = mouse.y - this.y;
                const distSq = dx * dx + dy * dy;
                const rSq = mouse.radius * mouse.radius;

                if (distSq < rSq && distSq > 0) {
                    const dist = Math.sqrt(distSq);
                    const force = (1 - dist / mouse.radius) * 1.4;
                    this.x -= (dx / dist) * force;
                    this.y -= (dy / dist) * force;
                }
            }
        }

        draw(ctx) {
            const { r, g, b } = this.color;

            if (this.type === 'sensor') {
                const ringAlpha = 0.2 + Math.sin(this.pulse) * 0.15;
                ctx.beginPath();
                ctx.arc(this.x, this.y, this.radius * 2.5, 0, Math.PI * 2);
                ctx.strokeStyle = `rgba(${r}, ${g}, ${b}, ${ringAlpha})`;
                ctx.lineWidth = 0.75;
                ctx.stroke();
            }

            ctx.beginPath();
            ctx.arc(this.x, this.y, this.radius, 0, Math.PI * 2);
            ctx.fillStyle = `rgba(${r}, ${g}, ${b}, 0.85)`;
            ctx.shadowColor = `rgba(${r}, ${g}, ${b}, 0.6)`;
            ctx.shadowBlur = 6;
            ctx.fill();
            ctx.shadowBlur = 0;
        }
    }

    class TelemetryPacket {
        constructor(source, target) {
            this.source = source;
            this.target = target;
            this.progress = 0;
            this.speed = 0.009 + Math.random() * 0.012;
            this.color = source.color;
            this.size = 1.3;
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
            ctx.fillStyle = `rgba(${r}, ${g}, ${b}, 0.95)`;
            ctx.shadowColor = `rgba(${r}, ${g}, ${b}, 0.9)`;
            ctx.shadowBlur = 8;
            ctx.fill();
            ctx.shadowBlur = 0;
        }
    }

    function resize() {
        const prevWidth = width;
        const prevHeight = height;
        dpr = Math.min(window.devicePixelRatio || 1, 2);
        width = window.innerWidth;
        height = window.innerHeight;
        mouse.radius = getMouseRadius();

        canvas.width = Math.floor(width * dpr);
        canvas.height = Math.floor(height * dpr);
        canvas.style.width = width + 'px';
        canvas.style.height = height + 'px';

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
            nodes.push(new CyberNode());
        }
        if (nodes.length > targetCount) {
            nodes.length = targetCount;
        }
    }

    function initNodes() {
        const count = getNodeCount();
        nodes = [];
        for (let i = 0; i < count; i++) {
            nodes.push(new CyberNode());
        }
        packets = [];
    }

    function loop() {
        if (!isRunning) return;

        ctx.clearRect(0, 0, width, height);

        const maxDist = getMaxDistance();
        const maxDistSq = maxDist * maxDist;

        for (let i = 0; i < nodes.length; i++) {
            nodes[i].update();
            nodes[i].draw(ctx);
        }

        for (let i = 0; i < nodes.length; i++) {
            for (let j = i + 1; j < nodes.length; j++) {
                const n1 = nodes[i];
                const n2 = nodes[j];
                const dx = n2.x - n1.x;
                const dy = n2.y - n1.y;
                const distSq = dx * dx + dy * dy;

                if (distSq < maxDistSq) {
                    const alpha = (1 - distSq / maxDistSq) * 0.35;
                    const r = Math.round((n1.color.r + n2.color.r) / 2);
                    const g = Math.round((n1.color.g + n2.color.g) / 2);
                    const b = Math.round((n1.color.b + n2.color.b) / 2);

                    ctx.beginPath();
                    ctx.moveTo(n1.x, n1.y);
                    ctx.lineTo(n2.x, n2.y);
                    ctx.strokeStyle = `rgba(${r}, ${g}, ${b}, ${alpha})`;
                    ctx.lineWidth = 0.8;
                    ctx.stroke();

                    if (packets.length < 6 && Math.random() < 0.0016) {
                        packets.push(new TelemetryPacket(n1, n2));
                    }
                }
            }
        }

        if (mouse.active) {
            const mDistSq = mouse.radius * mouse.radius;
            for (let i = 0; i < nodes.length; i++) {
                const n = nodes[i];
                const dx = mouse.x - n.x;
                const dy = mouse.y - n.y;
                const distSq = dx * dx + dy * dy;

                if (distSq < mDistSq) {
                    const alpha = (1 - distSq / mDistSq) * 0.45;
                    ctx.beginPath();
                    ctx.moveTo(n.x, n.y);
                    ctx.lineTo(mouse.x, mouse.y);
                    ctx.strokeStyle = `rgba(56, 189, 248, ${alpha})`;
                    ctx.lineWidth = 0.9;
                    ctx.stroke();
                }
            }
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

    function renderStaticFrame() {
        ctx.clearRect(0, 0, width, height);
        const maxDist = getMaxDistance();
        const maxDistSq = maxDist * maxDist;

        nodes.forEach(n => n.draw(ctx));

        for (let i = 0; i < nodes.length; i++) {
            for (let j = i + 1; j < nodes.length; j++) {
                const n1 = nodes[i];
                const n2 = nodes[j];
                const dx = n2.x - n1.x;
                const dy = n2.y - n1.y;
                const distSq = dx * dx + dy * dy;
                if (distSq < maxDistSq) {
                    const alpha = (1 - distSq / maxDistSq) * 0.22;
                    ctx.beginPath();
                    ctx.moveTo(n1.x, n1.y);
                    ctx.lineTo(n2.x, n2.y);
                    ctx.strokeStyle = `rgba(56, 189, 248, ${alpha})`;
                    ctx.lineWidth = 0.75;
                    ctx.stroke();
                }
            }
        }
    }

    function init() {
        resize();

        if (prefersReducedMotion.matches) {
            renderStaticFrame();
            return;
        }

        start();

        let resizeTimer;
        window.addEventListener('resize', () => {
            clearTimeout(resizeTimer);
            resizeTimer = setTimeout(() => {
                resize();
                if (prefersReducedMotion.matches) {
                    renderStaticFrame();
                }
            }, 100);
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
            } else if (!prefersReducedMotion.matches) {
                start();
            }
        });

        prefersReducedMotion.addEventListener('change', (e) => {
            if (e.matches) {
                stop();
                renderStaticFrame();
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

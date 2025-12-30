const HazeHunterGame = (() => {
    // Game State
    let gameState = 'start'; // start, playing, gameover
    let score = 0;
    let highScores = [];
    let playerName = '';

    // Game Loop Vars
    let canvas = null;
    let ctx = null;
    let requestRef = null;
    let player = { x: 0, width: 40, height: 40 };
    let items = [];
    let trails = [];
    let particles = [];
    let frame = 0;
    let speedMultiplier = 1;
    let keys = { left: false, right: false };

    // Constants
    const PLAYER_SPEED = 7;
    const SPAWN_RATE = 50;
    const PLAYER_Y = 120; // Player position fixed near top

    // DOM Elements
    let container = null;

    // Resize function needs to be scoped here to be accessible by open()
    const resize = () => {
        if (!canvas) return;
        canvas.width = canvas.clientWidth;
        canvas.height = canvas.clientHeight;
    };

    function loadHighScores() {
        fetch('/api/highscores')
            .then(res => res.json())
            .then(data => {
                highScores = data;
                renderHighScores(); // Re-render when data arrives
            })
            .catch(err => console.error("Error loading high scores:", err));
    }

    // Input Listeners
    function setupInputs() {
        const handleKeyDown = (e) => {
            if (e.key === 'ArrowLeft') keys.left = true;
            if (e.key === 'ArrowRight') keys.right = true;
        };
        const handleKeyUp = (e) => {
            if (e.key === 'ArrowLeft') keys.left = false;
            if (e.key === 'ArrowRight') keys.right = false;
        };

        window.addEventListener('keydown', handleKeyDown);
        window.addEventListener('keyup', handleKeyUp);
    }

    // --- DRAWING FUNCTION FOR THE CAN (SHARED) ---
    const drawHazeCan = (ctx, x, y) => {
        ctx.save();
        ctx.translate(x, y);

        const COPPER = '#c27c4e'; // Copper/Bronze color
        const BLACK = '#1a1a1a';  // Matte Black

        // 1. Shadow (Base)
        ctx.fillStyle = 'rgba(0,0,0,0.2)';
        ctx.beginPath();
        ctx.ellipse(14, 38, 12, 4, 0, 0, Math.PI * 2);
        ctx.fill();

        // 2. Can Body (Matte Black)
        ctx.fillStyle = BLACK;
        ctx.beginPath();
        ctx.moveTo(0, 4);
        ctx.lineTo(0, 36);
        ctx.quadraticCurveTo(14, 40, 28, 36); // Bottom curve
        ctx.lineTo(28, 4);
        ctx.closePath();
        ctx.fill();

        // Slight shine on black (Subtle matte reflection)
        ctx.fillStyle = 'rgba(255,255,255,0.05)';
        ctx.fillRect(4, 4, 4, 32);

        // 3. GRAPHICS (Copper)

        // Top text "Making Things Black" (Simplified line)
        ctx.fillStyle = COPPER;
        ctx.fillRect(6, 6, 16, 1);

        // -- THE SKULL --
        ctx.save();
        ctx.translate(14, 20); // Center of skull area

        // Flames (Top of head)
        ctx.fillStyle = COPPER;
        ctx.beginPath();
        ctx.moveTo(-6, -6);
        ctx.lineTo(-4, -10); // Flame 1
        ctx.lineTo(-2, -7);
        ctx.lineTo(0, -11);  // Flame 2 (Middle)
        ctx.lineTo(2, -7);
        ctx.lineTo(4, -10);  // Flame 3
        ctx.lineTo(6, -6);
        ctx.fill();

        // Skull Head
        ctx.fillStyle = '#e5e5e5'; // Bone white/greyish
        ctx.beginPath();
        ctx.arc(0, -2, 6, 0, Math.PI * 2); // Cranium
        ctx.fill();
        // Jaw
        ctx.fillRect(-3, 2, 6, 4);

        // Eyes (Large, empty)
        ctx.fillStyle = BLACK;
        ctx.beginPath();
        ctx.arc(-2, -2, 1.5, 0, Math.PI * 2);
        ctx.arc(2, -2, 1.5, 0, Math.PI * 2);
        ctx.fill();

        // Nose
        ctx.beginPath();
        ctx.moveTo(0, 0);
        ctx.lineTo(-0.5, 1.5);
        ctx.lineTo(0.5, 1.5);
        ctx.fill();

        // Teeth
        ctx.strokeStyle = BLACK;
        ctx.lineWidth = 0.5;
        ctx.beginPath();
        ctx.moveTo(-2, 2); ctx.lineTo(-2, 5);
        ctx.moveTo(0, 2); ctx.lineTo(0, 5);
        ctx.moveTo(2, 2); ctx.lineTo(2, 5);
        ctx.stroke();

        // Spade in forehead (Upside down)
        ctx.fillStyle = BLACK;
        ctx.font = "bold 4px Arial";
        ctx.textAlign = "center";
        ctx.fillText("♠", 0, -4);

        ctx.restore();

        // -- TEXT DETAILS --

        // "PISTONHEAD" Arc (Simplified as text above skull)
        ctx.fillStyle = COPPER;
        ctx.font = "bold 4px Arial";
        ctx.textAlign = "center";
        ctx.save();
        ctx.translate(14, 11);
        ctx.fillText("PISTONHEAD", 0, 0);
        ctx.restore();

        // "HAZE LAGER" (Bottom Right, Blocky)
        ctx.textAlign = "right";
        ctx.font = "900 6px Arial"; // Blocky
        ctx.fillStyle = COPPER;
        ctx.fillText("HAZE", 26, 30);
        ctx.font = "bold 4px Arial";
        ctx.fillText("LAGER", 26, 34);

        // "5.1%" (Bottom Left)
        ctx.textAlign = "left";
        ctx.font = "3px Arial";
        ctx.fillStyle = '#9ca3af'; // Greyish text
        ctx.fillText("5.1%", 2, 34);

        // Flames at bottom
        ctx.fillStyle = COPPER;
        ctx.beginPath();
        ctx.moveTo(0, 36);
        ctx.lineTo(4, 30);
        ctx.lineTo(8, 36);
        ctx.lineTo(12, 32);
        ctx.lineTo(16, 36);
        ctx.lineTo(20, 30);
        ctx.lineTo(24, 36);
        ctx.lineTo(28, 32);
        ctx.lineTo(28, 38);
        ctx.lineTo(0, 38);
        ctx.fill();

        // 4. Can Top (Rim)
        ctx.fillStyle = '#525252'; // Dark metallic
        ctx.beginPath();
        ctx.ellipse(14, 4, 14, 3.5, 0, 0, Math.PI * 2);
        ctx.fill();

        // Rim Outline (Copper hint)
        ctx.strokeStyle = COPPER;
        ctx.lineWidth = 0.5;
        ctx.stroke();

        // Pull Tab (Black)
        ctx.fillStyle = BLACK;
        ctx.beginPath();
        ctx.ellipse(14, 4, 3, 2, 0, 0, Math.PI * 2);
        ctx.fill();

        ctx.restore();
    };

    let gameToken = null;

    let heartbeatInterval = null;

    const startHeartbeat = () => {
        if (heartbeatInterval) clearInterval(heartbeatInterval);
        heartbeatInterval = setInterval(() => {
            if (!gameToken) return;
            fetch('/api/game/heartbeat', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(gameToken)
            }).catch(e => console.error("Heartbeat failed", e));
        }, 5000); // 5 seconds
    };

    const startGame = () => {
        // Fetch start token with cache busting
        fetch(`/api/game/start?t=${Date.now()}`)
            .then(res => {
                if (!res.ok) throw new Error("Server error");
                return res.json();
            })
            .then(data => {
                gameToken = data;
                console.log("Game token received:", gameToken);
                startHeartbeat(); // Start sending heartbeats
            })
            .catch(err => {
                console.error("Error fetching game token", err);
                alert("VARNING: Kunde inte anslut till servern. Dina poäng kommer INTE sparas. Kontrollera din anslutning.");
            });

        gameState = 'playing';
        score = 0;
        speedMultiplier = 1;
        items = [];
        trails = [];
        particles = [];
        frame = 0;

        // Center player
        if (canvas) {
            player.x = canvas.width / 2 - 20;
        }

        // Center player
        if (canvas) {
            // Ensure size is correct before starting
            resize();
            player.x = canvas.width / 2 - 20;
        }

        renderUI();

        // Start Loop
        if (requestRef) cancelAnimationFrame(requestRef);
        requestRef = requestAnimationFrame(gameLoop);
    };

    const handleGameOver = () => {
        cancelAnimationFrame(requestRef);
        if (heartbeatInterval) {
            clearInterval(heartbeatInterval); // Stop heartbeats
            heartbeatInterval = null;
        }
        console.log("Game Over - stopped heartbeats");
        gameState = 'gameover';
        renderUI();
    };

    const gameLoop = () => {
        if (!canvas) return;

        // Clear Canvas (White/Snow background)
        ctx.fillStyle = '#f0f9ff';
        ctx.fillRect(0, 0, canvas.width, canvas.height);

        const currentSpeed = (Math.random() * 0.5 + 4) * speedMultiplier;

        // Update Player Position
        if (keys.left && player.x > 0) {
            player.x -= PLAYER_SPEED;
        }
        if (keys.right && player.x < canvas.width - player.width) {
            player.x += PLAYER_SPEED;
        }

        // --- TRAIL LOGIC ---
        if (frame % 3 === 0) {
            trails.push({ x: player.x, y: PLAYER_Y + 30 });
        }

        // Move trails UP 
        for (let i = trails.length - 1; i >= 0; i--) {
            trails[i].y -= currentSpeed;
            if (trails[i].y < -50) {
                trails.splice(i, 1);
            }
        }

        // Draw Trails
        ctx.strokeStyle = 'rgba(200, 220, 240, 0.8)';
        ctx.lineWidth = 3;

        // Left Ski Track
        ctx.beginPath();
        for (let i = 0; i < trails.length; i++) {
            const p = trails[i];
            if (i === 0) ctx.moveTo(p.x + 10, p.y);
            else ctx.lineTo(p.x + 10, p.y);
        }
        ctx.stroke();

        // Right Ski Track
        ctx.beginPath();
        for (let i = 0; i < trails.length; i++) {
            const p = trails[i];
            if (i === 0) ctx.moveTo(p.x + 30, p.y);
            else ctx.lineTo(p.x + 30, p.y);
        }
        ctx.stroke();

        // Spawn Items
        if (frame % Math.floor(SPAWN_RATE / speedMultiplier) === 0) {
            const rand = Math.random();
            let type = 'tree';
            if (rand > 0.6) type = 'beer';
            else if (rand > 0.4) type = 'rock';

            items.push({
                x: Math.random() * (canvas.width - 40),
                y: canvas.height + 50, // Start below screen
                type: type,
                speed: currentSpeed
            });
        }

        // Update & Draw Items
        for (let i = items.length - 1; i >= 0; i--) {
            let item = items[i];
            item.y -= item.speed; // Move UP

            if (item.type === 'beer') {
                drawHazeCan(ctx, item.x, item.y + 10);
            } else {
                ctx.font = "32px Arial";
                let emoji = '🌲';
                if (item.type === 'rock') emoji = '🪨';
                ctx.fillText(emoji, item.x, item.y + 30);
            }

            // Collision Detection
            if (
                item.x < player.x + player.width - 5 &&
                item.x + 30 > player.x + 5 &&
                item.y < PLAYER_Y + player.height &&
                item.y + 30 > PLAYER_Y
            ) {
                if (item.type === 'beer') {
                    score += 10;
                    updateScoreUI();
                    speedMultiplier += 0.02;
                    items.splice(i, 1);
                } else {
                    handleGameOver();
                    return;
                }
            }

            // Remove items off screen
            if (item.y < -50) {
                items.splice(i, 1);
            }
        }

        // --- DRAW PLAYER ---
        ctx.save();
        const centerX = player.x + 20;
        const centerY = PLAYER_Y + 20;
        ctx.translate(centerX, centerY);

        let lean = 0;
        if (keys.left) lean = -0.2;
        if (keys.right) lean = 0.2;
        ctx.rotate(lean);

        // 0. Skis Shadow
        ctx.fillStyle = 'rgba(0,0,0,0.1)';
        ctx.beginPath();
        // roundRect might not be supported in all browsers on canvas ctx, fallback to rect if needed, but it's standard now
        if (ctx.roundRect) {
            ctx.roundRect(-14, -5, 10, 60, 4);
            ctx.roundRect(4, -5, 10, 60, 4);
        } else {
            ctx.fillRect(-14, -5, 10, 60);
            ctx.fillRect(4, -5, 10, 60);
        }
        ctx.fill();

        // 1. Skis
        ctx.fillStyle = '#dc2626';
        ctx.beginPath();
        if (ctx.roundRect) ctx.roundRect(-12, -10, 8, 55, 2);
        else ctx.fillRect(-12, -10, 8, 55);
        ctx.fill();
        ctx.beginPath();
        if (ctx.roundRect) ctx.roundRect(4, -10, 8, 55, 2);
        else ctx.fillRect(4, -10, 8, 55);
        ctx.fill();

        // Bindings
        ctx.fillStyle = '#374151';
        ctx.fillRect(-12, 15, 8, 8);
        ctx.fillRect(4, 15, 8, 8);

        // 2. Poles
        ctx.strokeStyle = '#9ca3af';
        ctx.lineWidth = 2;
        ctx.beginPath();
        ctx.moveTo(-18, 0);
        ctx.lineTo(-28, 35);
        ctx.stroke();
        ctx.beginPath();
        ctx.moveTo(18, 0);
        ctx.lineTo(28, 35);
        ctx.stroke();
        ctx.fillStyle = '#111827';
        ctx.beginPath();
        ctx.arc(-28, 32, 3, 0, Math.PI * 2);
        ctx.arc(28, 32, 3, 0, Math.PI * 2);
        ctx.fill();

        // 3. Body
        ctx.fillStyle = '#2563eb';
        ctx.beginPath();
        ctx.moveTo(-12, -15);
        ctx.lineTo(12, -15);
        ctx.lineTo(10, 15);
        ctx.lineTo(-10, 15);
        ctx.closePath();
        ctx.fill();

        ctx.strokeStyle = '#1d4ed8';
        ctx.lineWidth = 2;
        ctx.beginPath();
        ctx.moveTo(0, -15);
        ctx.lineTo(0, 15);
        ctx.stroke();

        // 4. Arms
        ctx.fillStyle = '#1d4ed8';
        ctx.beginPath();
        ctx.ellipse(-14, -5, 5, 10, -0.3, 0, Math.PI * 2);
        ctx.fill();
        ctx.beginPath();
        ctx.ellipse(14, -5, 5, 10, 0.3, 0, Math.PI * 2);
        ctx.fill();

        ctx.fillStyle = '#111827';
        ctx.beginPath();
        ctx.arc(-16, 2, 4, 0, Math.PI * 2);
        ctx.arc(16, 2, 4, 0, Math.PI * 2);
        ctx.fill();

        // 5. Head
        ctx.fillStyle = '#fbbf24';
        ctx.beginPath();
        ctx.arc(0, -22, 11, 0, Math.PI * 2);
        ctx.fill();

        // 6. Goggles
        ctx.fillStyle = '#111827';
        ctx.beginPath();
        if (ctx.roundRect) ctx.roundRect(-9, -25, 18, 8, 3);
        else ctx.fillRect(-9, -25, 18, 8);
        ctx.fill();

        // Lens reflection
        ctx.fillStyle = '#38bdf8';
        ctx.beginPath();
        if (ctx.roundRect) ctx.roundRect(-7, -23, 14, 4, 1);
        else ctx.fillRect(-7, -23, 14, 4);
        ctx.fill();
        ctx.fillStyle = '#ffffff';
        ctx.beginPath();
        ctx.arc(-5, -24, 1.5, 0, Math.PI * 2);
        ctx.fill();

        // 7. Scarf
        ctx.strokeStyle = '#ef4444';
        ctx.lineWidth = 4;
        ctx.lineCap = 'round';
        ctx.beginPath();
        ctx.moveTo(4, -14);
        const wiggle = Math.sin(frame * 0.2) * 4;
        ctx.quadraticCurveTo(12 + wiggle, -16, 18 + wiggle, -20 - (wiggle * 0.5));
        ctx.stroke();

        ctx.restore();

        // Speed lines / Snow particles
        if (frame % 5 === 0) {
            particles.push({ x: Math.random() * canvas.width, y: canvas.height + 10, speed: Math.random() * 10 + 5 });
        }
        ctx.fillStyle = 'rgba(255, 255, 255, 0.8)';
        for (let i = particles.length - 1; i >= 0; i--) {
            let p = particles[i];
            p.y -= p.speed;
            ctx.beginPath();
            ctx.arc(p.x, p.y, 2, 0, Math.PI * 2);
            ctx.fill();
            if (p.y < -10) particles.splice(i, 1);
        }

        frame++;
        requestRef = requestAnimationFrame(gameLoop);
    };



    let isSaving = false;

    const saveScore = () => {
        if (isSaving) return; // Prevent double clicks

        const input = document.getElementById('player-name-input');
        const name = input ? input.value : '';
        if (!name.trim()) return;

        isSaving = true;
        const btnSave = document.getElementById('btn-save-score');
        if (btnSave) {
            btnSave.disabled = true;
            btnSave.innerText = "Sparar...";
        }

        const newScore = {
            name: name,
            score: score,
            date: new Date().toLocaleDateString(),
            sessionId: gameToken ? gameToken.sessionId : null,
            signature: gameToken ? gameToken.signature : null
        };

        fetch('/api/highscore', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(newScore)
        })
            .then(res => {
                if (!res.ok) {
                    return res.json().then(data => { throw new Error(data.message || 'Error') });
                }
                return res.json();
            })
            .then(updatedScores => {
                highScores = updatedScores;
                playerName = '';
                gameState = 'start';
                gameToken = null; // Reset token
                renderUI();
            })
            .catch(err => {
                console.error("Failed to save score:", err);
                alert("Could not save score: " + err.message);
            })
            .finally(() => {
                isSaving = false;
                if (btnSave) {
                    btnSave.disabled = false;
                    btnSave.innerText = "SPARA & SPELA IGEN";
                }
            });
    };

    // UI Rendering (Vanilla JS replacement for React JSX)
    const renderUI = () => {
        // Hide all screens
        document.getElementById('screen-start').classList.add('hidden');
        document.getElementById('screen-gameover').classList.add('hidden');
        document.getElementById('game-score-display').innerText = `POÄNG: ${score}`;

        if (gameState === 'start') {
            document.getElementById('screen-start').classList.remove('hidden');
            renderHighScores();
        } else if (gameState === 'gameover') {
            document.getElementById('screen-gameover').classList.remove('hidden');
            document.getElementById('final-score').innerText = score;
        }
    };


    const renderHighScores = () => {
        const list = document.getElementById('highscore-list');
        if (!list) return;
        list.innerHTML = '';
        highScores.forEach((entry, idx) => {
            const li = document.createElement('li');
            li.className = "flex justify-between text-white border-b border-white/10 pb-1 last:border-0";
            li.innerHTML = `<span class="font-bold">${idx + 1}. ${entry.name}</span><span class="text-yellow-400 font-mono">${entry.score}</span>`;
            list.appendChild(li);
        });
        if (highScores.length > 0) document.getElementById('highscore-container').classList.remove('hidden');
    }

    const updateScoreUI = () => {
        const el = document.getElementById('game-score-display');
        if (el) el.innerText = `POÄNG: ${score}`;
    }

    // Touch Event Handling
    const handleTouchStart = (e) => {
        const touchX = e.touches[0].clientX;
        const screenWidth = window.innerWidth;
        if (touchX < screenWidth / 2) {
            keys.left = true;
            keys.right = false;
        } else {
            keys.right = true;
            keys.left = false;
        }
    };

    const handleTouchEnd = () => {
        keys.left = false;
        keys.right = false;
    };

    // Public init
    return {
        init: () => {
            console.log("HazeHunterGame.init() called");
            container = document.getElementById('game-modal');
            canvas = document.getElementById('game-canvas');
            if (!canvas) {
                console.error("Canvas element not found!");
                return;
            }
            ctx = canvas.getContext('2d');

            // Adjust canvas size initialization
            window.addEventListener('resize', resize);
            // Initial resize if visible (might be 0 if hidden)
            resize();

            if (window.lucide) window.lucide.createIcons();

            canvas.addEventListener('touchstart', handleTouchStart, { passive: false });
            canvas.addEventListener('touchend', handleTouchEnd);

            setupInputs();
            loadHighScores();

            // Bind Buttons
            const btnStart = document.getElementById('btn-start-game');
            if (btnStart) btnStart.addEventListener('click', startGame);

            const btnSave = document.getElementById('btn-save-score');
            if (btnSave) btnSave.addEventListener('click', saveScore);

            const btnBack = document.getElementById('btn-back-menu');
            if (btnBack) btnBack.addEventListener('click', () => {
                gameState = 'start';
                renderUI();
            });

            const btnClose = document.getElementById('btn-close-modal');
            if (btnClose) btnClose.addEventListener('click', () => {
                container.classList.add('hidden');
                cancelAnimationFrame(requestRef);
            });

            // Initial Render
            renderUI();
            console.log("HazeHunterGame initialized successfully");
        },
        open: () => {
            console.log("Opening game modal...");
            if (!container) {
                console.error("Container not found! Was init called?");
                // Try init again just in case
                // HazeHunterGame.init(); // Careful with recursion/scope, just log for now
                return;
            }
            container.classList.remove('hidden');
            // Force resize now that it is visible!
            resize();
            gameState = 'start';
            renderUI();
        }
    };
})();

// Explicitly attach to window to ensure global availability
window.HazeHunterGame = HazeHunterGame;

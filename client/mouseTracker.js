/**
 * ============================================================
 * mouseTracker.js — Stage 2: Mouse Behaviour Analysis
 * ============================================================
 * Responsibilities:
 *   - Listen to mousemove events for a set duration
 *   - Measure: movement speed, pauses, directional randomness
 *   - Combine metrics into a single behaviour score (0–100)
 *   - Higher score = more human-like movement
 *   - Return the numeric score
 *
 * Why this matters:
 *   Bots typically move in straight lines, at constant speeds,
 *   with no pauses. Real humans accelerate, slow down, jitter,
 *   and pause naturally. This heuristic helps detect automation.
 * ============================================================
 */

const MouseTracker = (() => {

  // ── Configuration ──────────────────────────────────────────

  const CONFIG = {
    // How long (ms) to collect mouse data before scoring
    collectionDurationMs: 3000,

    // Speed (px/ms) below which a movement is considered a "pause"
    pauseSpeedThreshold: 0.5,

    // Minimum number of data points for a reliable score
    minSamples: 10,

    // Score thresholds — score >= humanThreshold is considered human
    humanThreshold: 40,
  };

  // ── Private state ──────────────────────────────────────────

  let samples    = [];   // Array of { x, y, time } snapshots
  let isTracking = false;
  let onMoveHandler = null; // Reference needed for removeEventListener

  // ── Data collection ────────────────────────────────────────

  /**
   * startTracking()
   * Attaches a mousemove listener and collects coordinate samples.
   */
  function startTracking() {
    samples    = [];
    isTracking = true;

    onMoveHandler = (event) => {
      if (!isTracking) return;
      samples.push({
        x:    event.clientX,
        y:    event.clientY,
        time: performance.now(), // high-resolution timestamp (ms)
      });
    };

    document.addEventListener('mousemove', onMoveHandler);
    console.log('[MouseTracker] 🖱  Tracking started…');
  }

  /**
   * stopTracking()
   * Removes the event listener and returns collected samples.
   *
   * @returns {{ x: number, y: number, time: number }[]}
   */
  function stopTracking() {
    isTracking = false;
    document.removeEventListener('mousemove', onMoveHandler);
    onMoveHandler = null;
    console.log(`[MouseTracker] Stopped. Collected ${samples.length} samples.`);
    return [...samples];
  }

  // ── Metric calculations ────────────────────────────────────

  /**
   * calcSpeedVariance()
   * Humans accelerate and decelerate — their speed variance is HIGH.
   * Bots move at constant speed — variance is LOW or ZERO.
   *
   * Returns a score between 0–35.
   *
   * @param {object[]} pts - array of { x, y, time }
   * @returns {number}
   */
  function calcSpeedVariance(pts) {
    if (pts.length < 2) return 0;

    const speeds = [];
    for (let i = 1; i < pts.length; i++) {
      const dx = pts[i].x - pts[i - 1].x;
      const dy = pts[i].y - pts[i - 1].y;
      const dt = pts[i].time - pts[i - 1].time || 1; // avoid division by zero
      const speed = Math.sqrt(dx * dx + dy * dy) / dt; // px/ms
      speeds.push(speed);
    }

    // Mean
    const mean = speeds.reduce((a, b) => a + b, 0) / speeds.length;

    // Standard deviation
    const variance = speeds.reduce((acc, s) => acc + (s - mean) ** 2, 0) / speeds.length;
    const stdDev   = Math.sqrt(variance);

    // Map stdDev → 0–35 (cap at 5 px/ms variance for max score)
    return Math.min(35, (stdDev / 5) * 35);
  }

  /**
   * calcPauseScore()
   * Real users pause mid-movement (thinking, hovering).
   * Each detected pause adds to the score.
   *
   * Returns a score between 0–30.
   *
   * @param {object[]} pts
   * @returns {number}
   */
  function calcPauseScore(pts) {
    if (pts.length < 2) return 0;

    let pauseCount = 0;

    for (let i = 1; i < pts.length; i++) {
      const dx = pts[i].x - pts[i - 1].x;
      const dy = pts[i].y - pts[i - 1].y;
      const dt = pts[i].time - pts[i - 1].time || 1;
      const speed = Math.sqrt(dx * dx + dy * dy) / dt;

      if (speed < CONFIG.pauseSpeedThreshold) {
        pauseCount++;
      }
    }

    // Normalise: 1–5 pauses → full score range
    const ratio = Math.min(pauseCount / 5, 1);
    return ratio * 30;
  }

  /**
   * calcDirectionRandomness()
   * Humans change direction frequently and non-linearly.
   * We measure angle changes between consecutive movement vectors.
   *
   * Returns a score between 0–35.
   *
   * @param {object[]} pts
   * @returns {number}
   */
  function calcDirectionRandomness(pts) {
    if (pts.length < 3) return 0;

    const angleChanges = [];

    for (let i = 2; i < pts.length; i++) {
      // Vector from pt[i-2] → pt[i-1]
      const v1x = pts[i - 1].x - pts[i - 2].x;
      const v1y = pts[i - 1].y - pts[i - 2].y;

      // Vector from pt[i-1] → pt[i]
      const v2x = pts[i].x - pts[i - 1].x;
      const v2y = pts[i].y - pts[i - 1].y;

      const mag1 = Math.sqrt(v1x ** 2 + v1y ** 2);
      const mag2 = Math.sqrt(v2x ** 2 + v2y ** 2);

      if (mag1 === 0 || mag2 === 0) continue;

      // Dot product → cosine of angle between the two vectors
      const cos = (v1x * v2x + v1y * v2y) / (mag1 * mag2);
      // Clamp to [-1, 1] to avoid floating-point errors in acos()
      const angle = Math.acos(Math.max(-1, Math.min(1, cos)));
      angleChanges.push(angle); // radians
    }

    if (angleChanges.length === 0) return 0;

    // Average angle change (in radians)
    const avgChange = angleChanges.reduce((a, b) => a + b, 0) / angleChanges.length;

    // π/4 (45°) average change = max score; linear scale
    return Math.min(35, (avgChange / (Math.PI / 4)) * 35);
  }

  // ── Scoring ────────────────────────────────────────────────

  /**
   * calculateScore()
   * Combines the three sub-scores into a final 0–100 score.
   *
   * @param {object[]} pts - raw sample points
   * @returns {number} behaviour score (0–100)
   */
  function calculateScore(pts) {
    if (pts.length < CONFIG.minSamples) {
      console.warn('[MouseTracker] Not enough samples for reliable scoring.');
      return 0;
    }

    const speedScore     = calcSpeedVariance(pts);      // 0–35
    const pauseScore     = calcPauseScore(pts);         // 0–30
    const randomScore    = calcDirectionRandomness(pts); // 0–35

    const total = Math.round(speedScore + pauseScore + randomScore);

    console.log(
      `[MouseTracker] Score breakdown → ` +
      `speed: ${speedScore.toFixed(1)}, ` +
      `pauses: ${pauseScore.toFixed(1)}, ` +
      `randomness: ${randomScore.toFixed(1)}, ` +
      `TOTAL: ${total}/100`
    );

    return Math.min(100, total); // cap at 100
  }

  // ── Core API ───────────────────────────────────────────────

  /**
   * analyse()
   * Tracks mouse movement for CONFIG.collectionDurationMs ms,
   * then calculates and returns the behaviour score.
   *
   * @param {Function} [onTick] - optional callback(remainingSeconds)
   *        called every second so the UI can show a countdown.
   * @returns {Promise<number>} behaviour score (0–100)
   */
  async function analyse(onTick) {
    startTracking();

    // Countdown ticker (optional UI feedback)
    const totalSeconds = Math.ceil(CONFIG.collectionDurationMs / 1000);
    let elapsed = 0;

    await new Promise((resolve) => {
      const interval = setInterval(() => {
        elapsed++;
        if (typeof onTick === 'function') {
          onTick(totalSeconds - elapsed);
        }
        if (elapsed >= totalSeconds) {
          clearInterval(interval);
          resolve();
        }
      }, 1000);
    });

    const pts   = stopTracking();
    const score = calculateScore(pts);
    return score;
  }

  /**
   * isHuman()
   * Convenience boolean wrapper around analyse().
   *
   * @param {Function} [onTick]
   * @returns {Promise<{ human: boolean, score: number }>}
   */
  async function isHuman(onTick) {
    const score = await analyse(onTick);
    const human = score >= CONFIG.humanThreshold;
    console.log(`[MouseTracker] Human? ${human} (score: ${score}, threshold: ${CONFIG.humanThreshold})`);
    return { human, score };
  }

  // ── Public interface ───────────────────────────────────────
  return { analyse, isHuman, CONFIG };

})();

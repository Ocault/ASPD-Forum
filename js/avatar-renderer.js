/**
 * Avatar Renderer - Centralized avatar rendering logic
 * Supports both localStorage and external data sources
 */

const AvatarRenderer = (function() {
  'use strict';

  const STORAGE_KEY = 'aspd_avatar_config';

  // Default configuration
  const DEFAULT_CONFIG = {
    head: 0,
    eyes: 0,
    overlays: {
      static: false,
      crack: false
    }
  };

  // Muted palette
  const PALETTE = {
    bg:         '#0d0d0d',
    face:       '#2e2e2e',
    faceDark:   '#222222',
    faceLight:  '#3a3a3a',
    hair:       '#151515',
    hairLight:  '#1c1c1c',
    eye:        '#0a0a0a',
    eyeSocket:  '#1a1a1a',
    eyeGlint:   '#333333',
    nose:       '#262626',
    mouth:      '#1a1a1a',
    neck:       '#252525',
    shirt:      '#141414',
    shirtLight: '#1a1a1a',
    crack:      '#1a1a1a',
    static:     '#2a2a2a'
  };

  /**
   * Load avatar config from localStorage
   * @returns {Object} Avatar configuration
   */
  function loadFromStorage() {
    try {
      const saved = localStorage.getItem(STORAGE_KEY);
      if (saved) {
        return { ...DEFAULT_CONFIG, ...JSON.parse(saved) };
      }
    } catch (e) {}
    return { ...DEFAULT_CONFIG };
  }

  /**
   * Save avatar config to localStorage
   * @param {Object} config - Avatar configuration
   */
  function saveToStorage(config) {
    try {
      localStorage.setItem(STORAGE_KEY, JSON.stringify(config));
    } catch (e) {}
  }

  /**
   * Get avatar config from external source or localStorage
   * @param {Object|null} externalConfig - External avatar config (optional)
   * @returns {Object} Avatar configuration
   */
  function getConfig(externalConfig) {
    if (externalConfig && typeof externalConfig === 'object') {
      return { ...DEFAULT_CONFIG, ...externalConfig };
    }
    return loadFromStorage();
  }

  /**
   * Pixel drawing helper for full-size canvas (96x96)
   */
  function pxFull(ctx, x, y, w, h, c) {
    ctx.fillStyle = c;
    ctx.fillRect(x, y, w, h);
  }

  /**
   * Pixel drawing helper for scaled canvas
   */
  function pxScaled(ctx, x, y, w, h, c, scale) {
    ctx.fillStyle = c;
    ctx.fillRect(
      Math.floor(x * scale),
      Math.floor(y * scale),
      Math.max(1, Math.ceil(w * scale)),
      Math.max(1, Math.ceil(h * scale))
    );
  }

  // Head shape variants
  const heads = [
    // Type 0: Standard oval
    function(px) {
      px(28, 16, 40, 52, PALETTE.face);
      px(28, 16, 6, 52, PALETTE.faceDark);
      px(62, 16, 6, 52, PALETTE.faceLight);
      px(30, 62, 36, 4, PALETTE.faceDark);
    },
    // Type 1: Angular/sharp
    function(px) {
      px(30, 14, 36, 54, PALETTE.face);
      px(26, 20, 4, 40, PALETTE.faceDark);
      px(66, 20, 4, 40, PALETTE.faceDark);
      px(30, 14, 6, 54, PALETTE.faceDark);
      px(60, 14, 6, 54, PALETTE.faceLight);
      px(32, 62, 32, 6, PALETTE.faceDark);
    },
    // Type 2: Wider/square
    function(px) {
      px(24, 18, 48, 48, PALETTE.face);
      px(24, 18, 8, 48, PALETTE.faceDark);
      px(64, 18, 8, 48, PALETTE.faceLight);
      px(28, 60, 40, 6, PALETTE.faceDark);
    }
  ];

  // Eye style variants
  const eyes = [
    // Type 0: Standard
    function(px) {
      px(32, 34, 12, 10, PALETTE.eyeSocket);
      px(52, 34, 12, 10, PALETTE.eyeSocket);
      px(34, 36, 8, 6, PALETTE.eye);
      px(54, 36, 8, 6, PALETTE.eye);
      px(36, 37, 2, 2, PALETTE.eyeGlint);
      px(56, 37, 2, 2, PALETTE.eyeGlint);
    },
    // Type 1: Narrow/slit
    function(px) {
      px(32, 36, 14, 6, PALETTE.eyeSocket);
      px(50, 36, 14, 6, PALETTE.eyeSocket);
      px(34, 38, 10, 2, PALETTE.eye);
      px(52, 38, 10, 2, PALETTE.eye);
      px(38, 38, 2, 2, PALETTE.eyeGlint);
      px(56, 38, 2, 2, PALETTE.eyeGlint);
    },
    // Type 2: Hollow/deep
    function(px) {
      px(30, 32, 16, 14, PALETTE.eyeSocket);
      px(50, 32, 16, 14, PALETTE.eyeSocket);
      px(32, 34, 12, 10, PALETTE.eye);
      px(52, 34, 12, 10, PALETTE.eye);
      px(36, 36, 4, 4, PALETTE.eyeGlint);
      px(56, 36, 4, 4, PALETTE.eyeGlint);
    }
  ];

  // Overlay effects
  const overlays = {
    static: function(px, density) {
      const count = density || 80;
      for (let i = 0; i < count; i++) {
        const x = Math.floor(Math.random() * 96);
        const y = Math.floor(Math.random() * 96);
        const s = Math.random() > 0.5 ? 2 : 1;
        px(x, y, s, s, Math.random() > 0.5 ? PALETTE.static : PALETTE.bg);
      }
    },
    crack: function(px) {
      // Vertical crack
      px(52, 20, 2, 8, PALETTE.crack);
      px(54, 26, 2, 6, PALETTE.crack);
      px(52, 30, 2, 10, PALETTE.crack);
      px(50, 38, 2, 8, PALETTE.crack);
      px(52, 44, 2, 6, PALETTE.crack);
      px(54, 48, 2, 10, PALETTE.crack);
      px(52, 56, 2, 8, PALETTE.crack);
      // Branches
      px(54, 28, 4, 2, PALETTE.crack);
      px(48, 42, 4, 2, PALETTE.crack);
      px(54, 52, 6, 2, PALETTE.crack);
    }
  };

  /**
   * Render avatar to a canvas
   * @param {HTMLCanvasElement} canvas - Target canvas
   * @param {Object} config - Avatar configuration
   * @param {Object} options - Render options
   * @param {number} options.scale - Scale factor (default: 1 for 96x96, or auto-calculated from canvas size)
   * @param {number} options.staticDensity - Static overlay density
   */
  function render(canvas, config, options = {}) {
    const ctx = canvas.getContext('2d');
    const canvasWidth = canvas.width;
    const canvasHeight = canvas.height;
    
    // Check for custom image (admin uploaded)
    if (config && config.customImage) {
      const img = new Image();
      img.onload = function() {
        ctx.clearRect(0, 0, canvasWidth, canvasHeight);
        ctx.drawImage(img, 0, 0, canvasWidth, canvasHeight);
      };
      img.onerror = function() {
        // Fall back to placeholder on error
        renderPlaceholder(canvas);
      };
      img.src = config.customImage;
      return;
    }
    
    const scale = options.scale || (canvasWidth / 96);
    const staticDensity = options.staticDensity || (scale < 1 ? 15 : 80);

    // Create pixel helper with appropriate scale
    const px = scale === 1 
      ? (x, y, w, h, c) => pxFull(ctx, x, y, w, h, c)
      : (x, y, w, h, c) => pxScaled(ctx, x, y, w, h, c, scale);

    // Background
    px(0, 0, 96, 96, PALETTE.bg);

    // Hair back
    px(24, 6, 48, 20, PALETTE.hair);
    px(20, 14, 8, 24, PALETTE.hair);
    px(68, 14, 8, 24, PALETTE.hair);

    // Head (selected variant)
    const headIndex = Math.min(Math.max(0, config.head || 0), heads.length - 1);
    heads[headIndex](px);

    // Hair front
    px(28, 12, 40, 12, PALETTE.hair);
    px(32, 14, 8, 6, PALETTE.hairLight);
    px(48, 12, 12, 8, PALETTE.hairLight);
    px(56, 14, 6, 6, PALETTE.hairLight);

    // Eyes (selected variant)
    const eyesIndex = Math.min(Math.max(0, config.eyes || 0), eyes.length - 1);
    eyes[eyesIndex](px);

    // Nose
    px(46, 44, 4, 10, PALETTE.nose);
    px(44, 52, 8, 2, PALETTE.faceDark);

    // Mouth
    px(40, 58, 16, 2, PALETTE.mouth);
    px(42, 60, 12, 2, PALETTE.faceDark);

    // Neck
    px(38, 68, 20, 10, PALETTE.neck);

    // Shoulders
    px(14, 76, 68, 20, PALETTE.shirt);
    px(38, 76, 20, 4, PALETTE.shirtLight);

    // Collar
    px(40, 72, 16, 8, PALETTE.shirt);
    px(44, 68, 8, 6, PALETTE.neck);

    // Ear hints
    px(24, 36, 4, 12, PALETTE.faceDark);
    px(68, 36, 4, 12, PALETTE.faceDark);

    // Apply overlays
    if (config.overlays) {
      if (config.overlays.crack) overlays.crack(px);
      if (config.overlays.static) overlays.static(px, staticDensity);
    }
  }

  /**
   * Render placeholder avatar
   * @param {HTMLCanvasElement} canvas - Target canvas
   */
  function renderPlaceholder(canvas) {
    const ctx = canvas.getContext('2d');
    const scale = canvas.width / 96;
    const px = scale === 1 
      ? (x, y, w, h, c) => pxFull(ctx, x, y, w, h, c)
      : (x, y, w, h, c) => pxScaled(ctx, x, y, w, h, c, scale);

    px(0, 0, 96, 96, PALETTE.bg);
    px(28, 12, 40, 50, PALETTE.faceDark);
    px(30, 64, 36, 24, PALETTE.faceDark);
  }

  /**
   * Initialize avatars on page
   * @param {Object} options
   * @param {string} options.selector - CSS selector for avatar canvases (default: '.avatar-mini')
   * @param {Object|Function} options.configSource - Config object, or function(element) returning config
   */
  function initAvatars(options = {}) {
    const selector = options.selector || '.avatar-mini';
    const configSource = options.configSource || null;
    const canvases = document.querySelectorAll(selector);

    canvases.forEach(canvas => {
      let config;

      if (typeof configSource === 'function') {
        // Get config from function (for backend integration)
        config = configSource(canvas);
      } else if (configSource && typeof configSource === 'object') {
        // Use provided config object
        config = configSource;
      } else {
        // Fall back to localStorage
        config = loadFromStorage();
      }

      if (config && config.customImage) {
        // Custom image uploaded by admin
        render(canvas, config);
      } else if (config && (config.head !== undefined || config.eyes !== undefined)) {
        render(canvas, config);
      } else {
        renderPlaceholder(canvas);
      }
    });
  }

  // Public API
  return {
    STORAGE_KEY,
    DEFAULT_CONFIG,
    PALETTE,
    loadFromStorage,
    saveToStorage,
    getConfig,
    render,
    renderPlaceholder,
    initAvatars
  };

})();

// Export for module systems if available
if (typeof module !== 'undefined' && module.exports) {
  module.exports = AvatarRenderer;
}

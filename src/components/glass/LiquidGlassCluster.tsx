"use client";

import { useEffect, useRef, useState } from "react";
import type { CSSProperties } from "react";
import { GLASS_FRAG, GLASS_VERT } from "./shader";
import "./glass.css";

/* ==========================================================================
   Public API — preserved from the Originkit Glass Icon component
   ========================================================================== */

export type FontValue = {
  fontFamily?: string;
  fontSize?: string | number;
  fontWeight?: string | number;
  fontStyle?: string;
  letterSpacing?: string | number;
  lineHeight?: string | number;
};

export type BackdropGroup = {
  type?: "None" | "Image" | "Video" | "Text";
  image?: string;
  video?: string;
  text?: string;
  font?: FontValue;
  textColor?: string;
};

export type GlassGroup = {
  tint?: string;
  chromatic?: number;
  frost?: number;
};

export type OrientGroup = {
  angleX?: number;
  angleY?: number;
  angleZ?: number;
  offsetX?: number;
  offsetY?: number;
};

export type LiquidGlassClusterProps = {
  className?: string;
  style?: CSSProperties;

  background?: string;
  shape?: "X" | "Torus" | "Sphere" | "Logo";
  logo?: string;

  depth?: number;
  size?: number;
  speed?: number;
  direction?: "Clockwise" | "Counterclockwise";
  backdrop?: BackdropGroup;
  glass?: GlassGroup;
  orient?: OrientGroup;
};

/* ==========================================================================
   Original visual constants
   ========================================================================== */

const DEG = Math.PI / 180;
const TILT_RANGE = 0.5;
const IDLE_FLOAT = 0.05;
const DRAG_GAIN = 0.0055;
const MAX_PIXELS = 1_900_000;

const SHAPE_ID: Record<NonNullable<LiquidGlassClusterProps["shape"]>, number> =
  {
    X: 0,
    Sphere: 1,
    Torus: 2,
    Logo: 3,
  };

/* ==========================================================================
   Helpers (from the original component)
   ========================================================================== */

function parseColor(
  input: string | undefined,
  fallback: [number, number, number],
): [number, number, number] {
  if (!input) return fallback;
  const s = input.trim();
  if (s[0] === "#") {
    let h = s.slice(1);
    if (h.length === 3 || h.length === 4)
      h = h
        .split("")
        .map((c) => c + c)
        .join("");
    if (h.length >= 6) {
      const r = parseInt(h.slice(0, 2), 16) / 255;
      const g = parseInt(h.slice(2, 4), 16) / 255;
      const b = parseInt(h.slice(4, 6), 16) / 255;
      if (!isNaN(r) && !isNaN(g) && !isNaN(b)) return [r, g, b];
    }
    return fallback;
  }
  const m = s.match(/rgba?\(([^)]+)\)/i);
  if (m) {
    const p = m[1].split(",").map((v) => parseFloat(v));
    if (p.length >= 3) return [p[0] / 255, p[1] / 255, p[2] / 255];
  }
  return fallback;
}

function numOf(v: string | number | undefined, fallback: number): number {
  if (typeof v === "number") return Number.isFinite(v) ? v : fallback;
  if (typeof v === "string") {
    const n = parseFloat(v);
    if (Number.isFinite(n)) return n;
  }
  return fallback;
}

function rotYX(yaw: number, pitch: number): Float32Array {
  const cy = Math.cos(yaw);
  const sy = Math.sin(yaw);
  const cx = Math.cos(pitch);
  const sx = Math.sin(pitch);
  const m = new Float32Array(9);

  m[0] = cy;
  m[1] = 0;
  m[2] = -sy;

  m[3] = sy * sx;
  m[4] = cx;
  m[5] = cy * sx;

  m[6] = sy * cx;
  m[7] = -sx;
  m[8] = cy * cx;
  return m;
}

function transpose3(m: Float32Array): Float32Array {
  const o = new Float32Array(9);
  o[0] = m[0];
  o[1] = m[3];
  o[2] = m[6];
  o[3] = m[1];
  o[4] = m[4];
  o[5] = m[7];
  o[6] = m[2];
  o[7] = m[5];
  o[8] = m[8];
  return o;
}

function mul3(a: Float32Array, b: Float32Array): Float32Array {
  const o = new Float32Array(9);
  for (let c = 0; c < 3; c++)
    for (let r = 0; r < 3; r++)
      o[c * 3 + r] =
        a[r] * b[c * 3] +
        a[3 + r] * b[c * 3 + 1] +
        a[6 + r] * b[c * 3 + 2];
  return o;
}

function rotYXZ(yaw: number, pitch: number, roll: number): Float32Array {
  const base = rotYX(yaw, pitch);
  if (roll === 0) return base;
  const c = Math.cos(roll);
  const s = Math.sin(roll);
  const rz = new Float32Array([c, s, 0, -s, c, 0, 0, 0, 1]);
  return mul3(base, rz);
}

function buildEnvCanvas(): HTMLCanvasElement | null {
  if (typeof document === "undefined") return null;
  const canvas = document.createElement("canvas");
  canvas.width = 1024;
  canvas.height = 512;
  const ctx = canvas.getContext("2d");
  if (!ctx) return null;
  ctx.fillStyle = "#07090d";
  ctx.fillRect(0, 0, 1024, 512);

  const softbox = (
    x: number,
    y: number,
    w: number,
    h: number,
    intensity: number,
  ) => {
    const grd = ctx.createLinearGradient(x, y, x, y + h);
    grd.addColorStop(0, `rgba(255, 255, 255, ${intensity})`);
    grd.addColorStop(1, `rgba(60, 70, 84, ${intensity * 0.2})`);
    ctx.fillStyle = grd;
    ctx.shadowColor = "#dfefff";
    ctx.shadowBlur = 90;
    ctx.beginPath();
    const rr = (ctx as unknown as { roundRect?: (...a: unknown[]) => void })
      .roundRect;
    if (typeof rr === "function") rr.call(ctx, x, y, w, h, 60);
    else ctx.rect(x, y, w, h);
    ctx.fill();
  };
  softbox(50, 70, 280, 300, 0.95);
  softbox(690, 110, 300, 300, 0.8);
  softbox(360, -40, 300, 130, 0.75);
  ctx.shadowBlur = 0;
  return canvas;
}

/* ==========================================================================
   Asset preparation
   ========================================================================== */

type BackdropAssets = {
  texture: WebGLTexture | null;
  signature: string;
  video: HTMLVideoElement | null;
  needsUpload: boolean;
};

type LogoAssets = {
  texture: WebGLTexture | null;
  signature: string;
  image: HTMLImageElement | null;
  needsUpload: boolean;
};

function backdropSignature(b: BackdropGroup | undefined) {
  if (!b || !b.type || b.type === "None") return "none";
  return JSON.stringify(b);
}

function drawTextBackdrop(b: BackdropGroup): HTMLCanvasElement {
  const canvas = document.createElement("canvas");
  canvas.width = 1024;
  canvas.height = 512;
  const ctx = canvas.getContext("2d");
  if (!ctx) return canvas;

  const bg = ctx.createLinearGradient(0, 0, 1024, 512);
  bg.addColorStop(0, "#0a1118");
  bg.addColorStop(0.55, "#101b25");
  bg.addColorStop(1, "#0b0f19");
  ctx.fillStyle = bg;
  ctx.fillRect(0, 0, 1024, 512);

  const glow = ctx.createRadialGradient(260, 160, 0, 260, 160, 360);
  glow.addColorStop(0, "rgba(120, 230, 255, 0.22)");
  glow.addColorStop(1, "rgba(120, 230, 255, 0)");
  ctx.fillStyle = glow;
  ctx.fillRect(0, 0, 1024, 512);

  const font = b.font ?? {};
  const size = numOf(font.fontSize, 118);
  const family = font.fontFamily ?? "Space Grotesk, sans-serif";
  const weight = font.fontWeight ?? 500;
  const style = font.fontStyle ?? "normal";
  ctx.font = `${style} ${weight} ${size}px ${family}`;
  ctx.fillStyle = b.textColor ?? "#eaf6ff";
  ctx.textAlign = "center";
  ctx.textBaseline = "middle";
  ctx.shadowColor = "rgba(150, 235, 255, 0.35)";
  ctx.shadowBlur = 42;
  ctx.fillText(b.text ?? "", 512, 256);
  return canvas;
}

/* ==========================================================================
   Component
   ========================================================================== */

export default function LiquidGlassCluster(props: LiquidGlassClusterProps) {
  const {
    className,
    style,
    background,
    shape = "X",
    logo,
    depth = 1,
    size,
    speed = 0.6,
    direction = "Clockwise",
    backdrop,
    glass,
    orient,
  } = props;

  const containerRef = useRef<HTMLDivElement | null>(null);
  const canvasRef = useRef<HTMLCanvasElement | null>(null);
  const [webglFailed, setWebglFailed] = useState(false);

  const propsRef = useRef({
    shape,
    logo,
    depth,
    speed,
    direction,
    backdrop,
    glass,
    orient,
  });
  propsRef.current = {
    shape,
    logo,
    depth,
    speed,
    direction,
    backdrop,
    glass,
    orient,
  };

  const assetsRef = useRef<{
    loadBackdrop: (b?: BackdropGroup) => void;
    loadLogo: (src?: string) => void;
  } | null>(null);

  /* --------------------------- GPU lifecycle --------------------------- */

  useEffect(() => {
    const container = containerRef.current;
    const canvas = canvasRef.current;
    if (!container || !canvas) return;

    const gl = canvas.getContext("webgl", {
      alpha: true,
      antialias: true,
      premultipliedAlpha: false,
      depth: false,
      stencil: false,
      powerPreference: "high-performance",
      preserveDrawingBuffer: false,
    });

    if (!gl) {
      setWebglFailed(true);
      return;
    }

    const compile = (type: number, source: string) => {
      const shader = gl.createShader(type);
      if (!shader) return null;
      gl.shaderSource(shader, source);
      gl.compileShader(shader);
      if (!gl.getShaderParameter(shader, gl.COMPILE_STATUS)) {
        if (import.meta.env.DEV) {
          // eslint-disable-next-line no-console
          console.error(
            "[LiquidGlassCluster] shader compile failed:",
            gl.getShaderInfoLog(shader),
          );
        }
        gl.deleteShader(shader);
        return null;
      }
      return shader;
    };

    const vert = compile(gl.VERTEX_SHADER, GLASS_VERT);
    const frag = compile(gl.FRAGMENT_SHADER, GLASS_FRAG);
    if (!vert || !frag) {
      setWebglFailed(true);
      return;
    }

    const program = gl.createProgram();
    if (!program) {
      setWebglFailed(true);
      return;
    }
    gl.attachShader(program, vert);
    gl.attachShader(program, frag);
    gl.linkProgram(program);
    if (!gl.getProgramParameter(program, gl.LINK_STATUS)) {
      if (import.meta.env.DEV) {
        // eslint-disable-next-line no-console
        console.error(
          "[LiquidGlassCluster] program link failed:",
          gl.getProgramInfoLog(program),
        );
      }
      setWebglFailed(true);
      return;
    }

    gl.useProgram(program);
    gl.disable(gl.DEPTH_TEST);
    gl.enable(gl.BLEND);
    gl.blendFunc(gl.SRC_ALPHA, gl.ONE_MINUS_SRC_ALPHA);
    gl.clearColor(0, 0, 0, 0);

    const buffer = gl.createBuffer();
    gl.bindBuffer(gl.ARRAY_BUFFER, buffer);
    gl.bufferData(
      gl.ARRAY_BUFFER,
      new Float32Array([-1, -1, 3, -1, -1, 3]),
      gl.STATIC_DRAW,
    );
    const aPos = gl.getAttribLocation(program, "aPos");
    gl.enableVertexAttribArray(aPos);
    gl.vertexAttribPointer(aPos, 2, gl.FLOAT, false, 0, 0);

    const u = {
      res: gl.getUniformLocation(program, "uRes"),
      time: gl.getUniformLocation(program, "uTime"),
      pointer: gl.getUniformLocation(program, "uPointer"),
      invRot: gl.getUniformLocation(program, "uInvRot"),
      offset: gl.getUniformLocation(program, "uOffset"),
      fit: gl.getUniformLocation(program, "uFit"),
      depth: gl.getUniformLocation(program, "uDepth"),
      tint: gl.getUniformLocation(program, "uTint"),
      chroma: gl.getUniformLocation(program, "uChroma"),
      frost: gl.getUniformLocation(program, "uFrost"),
      shape: gl.getUniformLocation(program, "uShape"),
      tanHalf: gl.getUniformLocation(program, "uTanHalf"),
      backdrop: gl.getUniformLocation(program, "uBackdrop"),
      hasBackdrop: gl.getUniformLocation(program, "uHasBackdrop"),
      env: gl.getUniformLocation(program, "uEnv"),
      logo: gl.getUniformLocation(program, "uLogo"),
      hasLogo: gl.getUniformLocation(program, "uHasLogo"),
    };

    const makeTexture = () => {
      const tex = gl.createTexture();
      gl.bindTexture(gl.TEXTURE_2D, tex);
      gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_WRAP_S, gl.CLAMP_TO_EDGE);
      gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_WRAP_T, gl.CLAMP_TO_EDGE);
      gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_MIN_FILTER, gl.LINEAR);
      gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_MAG_FILTER, gl.LINEAR);
      gl.texImage2D(
        gl.TEXTURE_2D,
        0,
        gl.RGBA,
        1,
        1,
        0,
        gl.RGBA,
        gl.UNSIGNED_BYTE,
        new Uint8Array([0, 0, 0, 0]),
      );
      return tex;
    };

    const envTexture = makeTexture();
    const envCanvas = buildEnvCanvas();
    if (envCanvas) {
      gl.bindTexture(gl.TEXTURE_2D, envTexture);
      gl.pixelStorei(gl.UNPACK_FLIP_Y_WEBGL, 1);
      gl.texImage2D(
        gl.TEXTURE_2D,
        0,
        gl.RGBA,
        gl.RGBA,
        gl.UNSIGNED_BYTE,
        envCanvas,
      );
      gl.pixelStorei(gl.UNPACK_FLIP_Y_WEBGL, 0);
    }

    const backdropAssets: BackdropAssets = {
      texture: makeTexture(),
      signature: "",
      video: null,
      needsUpload: false,
    };
    const logoAssets: LogoAssets = {
      texture: makeTexture(),
      signature: "",
      image: null,
      needsUpload: false,
    };

    const uploadBackdropCanvas = (
      source: HTMLCanvasElement | HTMLImageElement | HTMLVideoElement,
    ) => {
      if (!backdropAssets.texture) return;
      gl.bindTexture(gl.TEXTURE_2D, backdropAssets.texture);
      gl.pixelStorei(gl.UNPACK_FLIP_Y_WEBGL, 1);
      gl.texImage2D(
        gl.TEXTURE_2D,
        0,
        gl.RGBA,
        gl.RGBA,
        gl.UNSIGNED_BYTE,
        source,
      );
      gl.pixelStorei(gl.UNPACK_FLIP_Y_WEBGL, 0);
      backdropAssets.needsUpload = false;
    };

    const teardownBackdrop = () => {
      if (backdropAssets.video) {
        backdropAssets.video.pause();
        backdropAssets.video.removeAttribute("src");
        backdropAssets.video.load();
        backdropAssets.video = null;
      }
    };

    const loadBackdrop = (b?: BackdropGroup) => {
      const sig = backdropSignature(b);
      if (sig === backdropAssets.signature) return;
      backdropAssets.signature = sig;
      teardownBackdrop();
      backdropAssets.needsUpload = false;

      if (!b || !b.type || b.type === "None") return;

      if (b.type === "Text") {
        uploadBackdropCanvas(drawTextBackdrop(b));
        return;
      }

      if (b.type === "Image" && b.image) {
        const img = new Image();
        img.crossOrigin = "anonymous";
        img.onload = () => {
          if (backdropAssets.signature === sig) uploadBackdropCanvas(img);
        };
        img.src = b.image;
        return;
      }

      if (b.type === "Video" && b.video) {
        const video = document.createElement("video");
        video.crossOrigin = "anonymous";
        video.loop = true;
        video.muted = true;
        video.playsInline = true;
        video.autoplay = true;
        video.src = b.video;
        video.style.display = "none";
        backdropAssets.video = video;
        video.play().catch(() => undefined);
        return;
      }
    };

    const loadLogo = (src?: string) => {
      const sig = src ?? "";
      if (sig === logoAssets.signature) return;
      logoAssets.signature = sig;
      logoAssets.needsUpload = false;
      if (!src) return;
      const img = new Image();
      img.crossOrigin = "anonymous";
      img.onload = () => {
        if (logoAssets.signature !== sig || !logoAssets.texture) return;
        logoAssets.image = img;
        gl.bindTexture(gl.TEXTURE_2D, logoAssets.texture);
        gl.pixelStorei(gl.UNPACK_FLIP_Y_WEBGL, 1);
        gl.texImage2D(gl.TEXTURE_2D, 0, gl.RGBA, gl.RGBA, gl.UNSIGNED_BYTE, img);
        gl.pixelStorei(gl.UNPACK_FLIP_Y_WEBGL, 0);
      };
      img.src = src;
    };

    assetsRef.current = { loadBackdrop, loadLogo };
    loadBackdrop(propsRef.current.backdrop);
    loadLogo(propsRef.current.logo);

    /* --------------------------- sizing --------------------------- */

    let needsRender = true;
    let visible = true;
    let quality = 1;
    let fits = false;
    const resize = () => {
      const rect = container.getBoundingClientRect();
      if (rect.width < 2 || rect.height < 2) {
        fits = false;
        return;
      }
      fits = true;
      const dpr = Math.min(window.devicePixelRatio || 1, 1.75) * quality;
      let w = Math.max(2, Math.round(rect.width * dpr));
      let h = Math.max(2, Math.round(rect.height * dpr));
      if (w * h > MAX_PIXELS) {
        const s = Math.sqrt(MAX_PIXELS / (w * h));
        w = Math.max(2, Math.round(w * s));
        h = Math.max(2, Math.round(h * s));
      }
      if (canvas.width !== w || canvas.height !== h) {
        canvas.width = w;
        canvas.height = h;
        gl.viewport(0, 0, w, h);
        needsRender = true;
      }
    };

    const resizeObserver = new ResizeObserver(resize);
    resizeObserver.observe(container);
    resize();
    needsRender = true;

    /* --------------------------- interaction --------------------------- */

    const pointer = { x: 0, y: 0 };
    const hover = { x: 0, y: 0 };
    let dragYaw = 0;
    let dragPitch = 0;
    let dragging = false;
    let lastPointer: { x: number; y: number } | null = null;

    const onPointerMove = (event: PointerEvent) => {
      const rect = container.getBoundingClientRect();
      if (!rect.width || !rect.height) return;
      pointer.x = ((event.clientX - rect.left) / rect.width - 0.5) * 2;
      pointer.y = ((event.clientY - rect.top) / rect.height - 0.5) * 2;

      if (dragging && lastPointer && event.pointerType === "mouse") {
        dragYaw += (event.clientX - lastPointer.x) * DRAG_GAIN;
        dragPitch += (event.clientY - lastPointer.y) * DRAG_GAIN * 0.7;
        dragPitch = Math.max(-0.7, Math.min(0.7, dragPitch));
        lastPointer = { x: event.clientX, y: event.clientY };
      }
      needsRender = true;
    };

    const onPointerLeave = () => {
      pointer.x = 0;
      pointer.y = 0;
      needsRender = true;
    };

    const onPointerDown = (event: PointerEvent) => {
      if (event.pointerType !== "mouse") return;
      dragging = true;
      lastPointer = { x: event.clientX, y: event.clientY };
      container.setPointerCapture?.(event.pointerId);
    };

    const onPointerUp = (event: PointerEvent) => {
      dragging = false;
      lastPointer = null;
      if (container.hasPointerCapture?.(event.pointerId)) {
        container.releasePointerCapture(event.pointerId);
      }
    };

    container.addEventListener("pointermove", onPointerMove);
    container.addEventListener("pointerleave", onPointerLeave);
    container.addEventListener("pointerdown", onPointerDown);
    container.addEventListener("pointerup", onPointerUp);
    container.addEventListener("pointercancel", onPointerUp);

    /* --------------------------- visibility --------------------------- */

    const intersectionObserver = new IntersectionObserver(
      (entries) => {
        visible = entries.some((entry) => entry.isIntersecting);
        if (visible) {
          needsRender = true;
          schedule();
        }
      },
      { rootMargin: "120px" },
    );
    intersectionObserver.observe(container);

    const onVisibility = () => {
      if (document.visibilityState === "visible") {
        needsRender = true;
        schedule();
      }
    };
    document.addEventListener("visibilitychange", onVisibility);

    const motionQuery = window.matchMedia("(prefers-reduced-motion: reduce)");
    let reduced = motionQuery.matches;
    const onMotionChange = () => {
      reduced = motionQuery.matches;
      needsRender = true;
    };
    motionQuery.addEventListener?.("change", onMotionChange);

    /* --------------------------- frame loop --------------------------- */

    let raf = 0;
    let elapsed = 0;
    let last = performance.now();
    let frameAvg = 16.7;
    let frames = 0;
    let resizeCooldown = 0;
    let disposed = false;

    const draw = (now: number) => {
      const delta = Math.min(50, now - last);
      last = now;
      frameAvg = frameAvg * 0.92 + delta * 0.08;
      frames++;

      if (!reduced) elapsed += delta / 1000;

      const p = propsRef.current;
      const ease = reduced ? 1 : 0.06;
      hover.x += (pointer.x - hover.x) * ease;
      hover.y += (pointer.y - hover.y) * ease;

      if (!reduced || needsRender) {
        gl.clear(gl.COLOR_BUFFER_BIT);
        gl.useProgram(program);

        const rect = container.getBoundingClientRect();
        const aspect = rect.height > 0 ? rect.width / rect.height : 1;
        const directionSign =
          p.direction === "Counterclockwise" ? -1 : 1;
        const speed = Math.max(0, p.speed ?? 0.6);
        const idle = reduced ? 0 : elapsed * 0.075 * speed * directionSign;

        const baseYaw = (p.orient?.angleY ?? 0) * DEG;
        const basePitch = (p.orient?.angleX ?? 0) * DEG;
        const baseRoll = (p.orient?.angleZ ?? 0) * DEG;

        const yaw =
          baseYaw +
          idle +
          hover.x * TILT_RANGE * 0.5 +
          dragYaw +
          Math.sin(elapsed * 0.23) * IDLE_FLOAT;
        const pitch = Math.max(
          -1.1,
          Math.min(
            1.1,
            basePitch +
              hover.y * TILT_RANGE * 0.42 +
              dragPitch +
              Math.sin(elapsed * 0.31) * IDLE_FLOAT * 0.8,
          ),
        );
        const roll = baseRoll + Math.sin(elapsed * 0.19) * 0.015;

        const matrix = transpose3(rotYXZ(yaw, pitch, roll));

        gl.uniform2f(u.res, canvas.width, canvas.height);
        gl.uniform1f(u.time, elapsed);
        gl.uniform2f(u.pointer, hover.x, hover.y);
        gl.uniformMatrix3fv(u.invRot, false, matrix);
        gl.uniform2f(
          u.offset,
          p.orient?.offsetX ?? 0,
          p.orient?.offsetY ?? 0,
        );
        gl.uniform1f(u.fit, Math.max(0.7, Math.min(1, aspect / 1.15)));
        gl.uniform1f(u.depth, numOf(p.depth, 1));
        gl.uniform3f(
          u.tint,
          ...parseColor(p.glass?.tint, [0.82, 0.97, 1]),
        );
        gl.uniform1f(u.chroma, numOf(p.glass?.chromatic, 0.35));
        gl.uniform1f(u.frost, numOf(p.glass?.frost, 0.28));
        gl.uniform1i(u.shape, SHAPE_ID[p.shape ?? "X"] ?? 0);
        gl.uniform1f(
          u.tanHalf,
          Math.tan((45 * Math.PI) / 180 / 2),
        );

        if (
          backdropAssets.video &&
          backdropAssets.video.readyState >= 2 &&
          backdropAssets.signature !== "none"
        ) {
          uploadBackdropCanvas(backdropAssets.video);
        }

        gl.activeTexture(gl.TEXTURE0);
        gl.bindTexture(gl.TEXTURE_2D, backdropAssets.texture);
        gl.uniform1i(u.backdrop, 0);
        gl.uniform1f(
          u.hasBackdrop,
          backdropAssets.signature !== "none" &&
            backdropAssets.texture !== null
            ? 1
            : 0,
        );

        gl.activeTexture(gl.TEXTURE1);
        gl.bindTexture(gl.TEXTURE_2D, envTexture);
        gl.uniform1i(u.env, 1);

        gl.activeTexture(gl.TEXTURE2);
        gl.bindTexture(gl.TEXTURE_2D, logoAssets.texture);
        gl.uniform1i(u.logo, 2);
        gl.uniform1f(
          u.hasLogo,
          logoAssets.signature && logoAssets.image ? 1 : 0,
        );

        gl.drawArrays(gl.TRIANGLES, 0, 3);
        needsRender = false;
      }

      /* adaptive resolution keeps the glass smooth on modest GPUs */
      if (!reduced && frames > 48 && resizeCooldown <= 0) {
        if (frameAvg > 24.5 && quality > 0.6) {
          quality = Math.max(0.6, quality - 0.1);
          resize();
          frames = 0;
          resizeCooldown = 70;
        } else if (frameAvg < 14 && quality < 1) {
          quality = Math.min(1, quality + 0.05);
          resize();
          frames = 0;
          resizeCooldown = 70;
        }
      }
      resizeCooldown--;

      if (!disposed) raf = requestAnimationFrame(loop);
    };

    const loop = (now: number) => {
      raf = 0;
      if (disposed) return;
      if (!visible || document.visibilityState !== "visible" || !fits) {
        raf = requestAnimationFrame(loop);
        last = now;
        return;
      }
      draw(now);
    };

    const schedule = () => {
      if (!raf && !disposed) raf = requestAnimationFrame(loop);
    };

    schedule();

    return () => {
      disposed = true;
      cancelAnimationFrame(raf);
      resizeObserver.disconnect();
      intersectionObserver.disconnect();
      document.removeEventListener("visibilitychange", onVisibility);
      motionQuery.removeEventListener?.("change", onMotionChange);
      container.removeEventListener("pointermove", onPointerMove);
      container.removeEventListener("pointerleave", onPointerLeave);
      container.removeEventListener("pointerdown", onPointerDown);
      container.removeEventListener("pointerup", onPointerUp);
      container.removeEventListener("pointercancel", onPointerUp);
      teardownBackdrop();
      gl.deleteTexture(envTexture);
      gl.deleteTexture(backdropAssets.texture);
      gl.deleteTexture(logoAssets.texture);
      gl.deleteBuffer(buffer);
      gl.deleteProgram(program);
      gl.deleteShader(vert);
      gl.deleteShader(frag);
      assetsRef.current = null;
    };
    // The renderer is intentionally created once; live props are read by ref.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  /* Keep scene assets in sync with props without rebuilding the context. */
  useEffect(() => {
    assetsRef.current?.loadBackdrop(backdrop);
  }, [backdrop]);

  useEffect(() => {
    assetsRef.current?.loadLogo(logo);
  }, [logo]);

  const wrapperStyle: CSSProperties = {
    ...(size ? { width: size, height: size } : null),
    ...(background ? { background } : null),
    ...style,
  };

  return (
    <div
      ref={containerRef}
      className={`lgc ${className ?? ""}`}
      style={wrapperStyle}
      role="img"
      aria-label="Three liquid glass forms refracting a dark studio environment"
    >
      <div className="lgc__glow" aria-hidden="true" />
      <canvas
        ref={canvasRef}
        className="lgc__canvas"
        aria-hidden="true"
        data-webgl={webglFailed ? "fallback" : "live"}
      />
      {webglFailed && (
        <div className="lgc__fallback" aria-hidden="true">
          <span className="lgc__shard lgc__shard--a" />
          <span className="lgc__shard lgc__shard--b" />
          <span className="lgc__shard lgc__shard--c" />
        </div>
      )}
      <div className="lgc__vignette" aria-hidden="true" />
    </div>
  );
}

import { useEffect, useRef, useState } from "react";
import type { CSSProperties } from "react";

export type FloatingGlassShape = "Torus" | "X" | "Sphere";

export interface FloatingGlassIconProps {
  text?: string;
  shape?: FloatingGlassShape;
  size?: number;
  depth?: number;
  chromatic?: number;
  frost?: number;
  speed?: number;
  tint?: [number, number, number];
  className?: string;
  style?: CSSProperties;
  onInteractiveChange?: (info: { shape: FloatingGlassShape; text: string }) => void;
}

const SHAPE_MAP: Record<FloatingGlassShape, number> = {
  X: 0,
  Torus: 1,
  Sphere: 2,
};

const VS = "attribute vec2 aPos; void main(){ gl_Position = vec4(aPos, 0.0, 1.0); }";

const FS = `
precision highp float;
uniform vec2 uRes;
uniform mat3 uRot;
uniform vec2 uOff;
uniform float uSize, uDepth, uChroma, uFrost;
uniform vec3 uTint;
uniform int uShape;
uniform sampler2D uPlate;

float smin(float a, float b, float k){
  float h = clamp(0.5 + 0.5*(b-a)/k, 0.0, 1.0);
  return mix(b, a, h) - k*h*(1.0-h);
}

float sdRB(vec3 p, vec3 b, float r){
  vec3 q = abs(p) - b;
  return length(max(q, 0.0)) + min(max(q.x, max(q.y, q.z)), 0.0) - r;
}

vec3 rotZ(vec3 p, float a){
  float c = cos(a), s = sin(a);
  return vec3(c*p.x - s*p.y, s*p.x + c*p.y, p.z);
}

float map(vec3 w){
  vec3 p = (w - vec3(uOff, 0.0)) * uRot / uSize;
  float d;
  if (uShape == 0) {
    float a = sdRB(rotZ(p, 0.785398), vec3(0.95, 0.17, 0.17), 0.14);
    float b = sdRB(rotZ(p, -0.785398), vec3(0.95, 0.17, 0.17), 0.14);
    d = smin(a, b, 0.12);
  } else if (uShape == 1) {
    vec2 q = vec2(length(p.xy) - 0.72, p.z);
    d = length(q) - 0.3;
  } else {
    d = length(p) - 0.95;
  }
  return d * uSize;
}

vec3 nrm(vec3 p){
  vec2 e = vec2(0.002, -0.002);
  return normalize(e.xyy*map(p + e.xyy) + e.yyx*map(p + e.yyx) + e.yxy*map(p + e.yxy) + e.xxx*map(p + e.xxx));
}

vec3 plate(vec2 uv, float r){
  vec3 c = texture2D(uPlate, clamp(uv, 0.0, 1.0)).rgb;
  if (r < 0.0005) return c;
  vec3 s = c;
  for (int i = 0; i < 8; i++) {
    float a = float(i) * 0.785398 + 0.3;
    vec2 d = vec2(cos(a), sin(a));
    s += texture2D(uPlate, clamp(uv + d * r, 0.0, 1.0)).rgb;
    s += texture2D(uPlate, clamp(uv + d * r * 0.5, 0.0, 1.0)).rgb;
  }
  return s / 17.0;
}

vec3 samp(float ior, vec3 n, vec3 rd, vec2 uv, vec2 cuv, float r){
  vec3 rf = refract(rd, n, 1.0 / ior);
  vec2 off = (rf.xy - rd.xy) * uDepth * 0.3 + (cuv - uv) * 0.1 * uDepth;
  return plate(uv + off, r);
}

void main(){
  vec2 uv = gl_FragCoord.xy / uRes;
  vec2 ndc = uv * 2.0 - 1.0;
  vec3 ro = vec3(0.0, 0.0, 5.0);
  vec3 rd = normalize(vec3(ndc * 0.41421356, -1.0));
  float t = 0.0, minD = 1e9;
  vec3 pm = ro;
  for (int i = 0; i < 72; i++) {
    vec3 p = ro + rd * t;
    float d = map(p);
    if (d < minD) { minD = d; pm = p; }
    if (d < 0.0008 || t > 9.0) break;
    t += d;
  }
  vec3 bg = plate(uv, 0.0);
  float alpha = 1.0 - smoothstep(0.001, 0.012, minD);
  if (alpha <= 0.0) { gl_FragColor = vec4(bg, 1.0); return; }
  vec3 n = nrm(pm);
  float ndv = clamp(dot(n, -rd), 0.0, 1.0);
  float r = uFrost * 0.03;
  vec2 cuv = vec2(0.5) + uOff / 4.142;
  float spread = uChroma * 0.06;
  vec3 col = vec3(
    samp(1.5 - spread, n, rd, uv, cuv, r).r,
    samp(1.5, n, rd, uv, cuv, r).g,
    samp(1.5 + spread, n, rd, uv, cuv, r).b
  );
  col *= mix(vec3(1.0), uTint, 0.9);
  vec3 rr = reflect(rd, n);
  float band = 1.0 - smoothstep(0.55, 0.8, abs(rr.y));
  float box = smoothstep(0.35, 0.55, -rr.x) * band + smoothstep(0.35, 0.55, rr.x) * band + smoothstep(0.55, 0.85, rr.y) * 0.9;
  float fres = 0.04 + 0.96 * pow(1.0 - ndv, 4.0);
  float key = pow(max(dot(rr, normalize(vec3(-0.5, 0.7, 0.6))), 0.0), 60.0);
  float rim = pow(1.0 - ndv, 2.5);
  col = col * (1.0 - 0.25 * rim) + vec3(box * (0.25 + fres * 1.2) * 0.8 + key * 0.9 + rim * 0.08);
  gl_FragColor = vec4(mix(bg, col, alpha), 1.0);
}
`;

function mul3(a: Float32Array, b: Float32Array): Float32Array {
  const o = new Float32Array(9);
  for (let c = 0; c < 3; c++) {
    for (let r = 0; r < 3; r++) {
      o[c * 3 + r] =
        a[r] * b[c * 3] +
        a[3 + r] * b[c * 3 + 1] +
        a[6 + r] * b[c * 3 + 2];
    }
  }
  return o;
}

function Rx(a: number): Float32Array {
  const c = Math.cos(a), s = Math.sin(a);
  return new Float32Array([1, 0, 0, 0, c, s, 0, -s, c]);
}

function Ry(a: number): Float32Array {
  const c = Math.cos(a), s = Math.sin(a);
  return new Float32Array([c, 0, -s, 0, 1, 0, s, 0, c]);
}

export default function FloatingGlassIcon({
  text = "CITADEL",
  shape = "Torus",
  size = 0.9,
  depth = 1.0,
  chromatic = 1.0,
  frost = 0.12,
  speed = 1.0,
  tint = [1.0, 1.0, 1.0],
  className = "",
  style,
}: FloatingGlassIconProps) {
  const canvasRef = useRef<HTMLCanvasElement | null>(null);
  const containerRef = useRef<HTMLDivElement | null>(null);
  const [webglFailed, setWebglFailed] = useState(false);

  // References for live shader uniforms without context recreation
  const stateRef = useRef({
    text,
    shape: SHAPE_MAP[shape],
    size,
    depth,
    chromatic,
    frost,
    speed,
    tint,
    reducedMotion: false,
  });

  useEffect(() => {
    stateRef.current.text = text;
    stateRef.current.shape = SHAPE_MAP[shape];
    stateRef.current.size = size;
    stateRef.current.depth = depth;
    stateRef.current.chromatic = chromatic;
    stateRef.current.frost = frost;
    stateRef.current.speed = speed;
    stateRef.current.tint = tint;
  }, [text, shape, size, depth, chromatic, frost, speed, tint]);

  // Plate texture drawer ref
  const plateDrawerRef = useRef<(() => void) | null>(null);

  useEffect(() => {
    plateDrawerRef.current?.();
  }, [text]);

  useEffect(() => {
    const cv = canvasRef.current;
    if (!cv) return;

    let gl: WebGLRenderingContext | null = null;
    try {
      gl = cv.getContext("webgl", { antialias: false, alpha: false, powerPreference: "high-performance" });
    } catch {
      setWebglFailed(true);
      return;
    }

    if (!gl) {
      setWebglFailed(true);
      return;
    }

    // Plate canvas for background refraction
    const P = document.createElement("canvas");
    P.width = P.height = 1024;

    let tex: WebGLTexture | null = null;
    const uploadPlate = () => {
      if (!gl || !tex) return;
      gl.bindTexture(gl.TEXTURE_2D, tex);
      gl.pixelStorei(gl.UNPACK_FLIP_Y_WEBGL, true);
      gl.texImage2D(gl.TEXTURE_2D, 0, gl.RGBA, gl.RGBA, gl.UNSIGNED_BYTE, P);
    };

    const drawPlate = () => {
      const g = P.getContext("2d");
      if (!g) return;
      const W = 1024;
      // Base background gradient: deep obsidian to cyber slate
      const base = g.createLinearGradient(0, 0, W, W);
      base.addColorStop(0, "#0b0d12");
      base.addColorStop(1, "#151922");
      g.fillStyle = base;
      g.fillRect(0, 0, W, W);

      // Warm radial glow on bottom-left (warm amber/coral)
      const warm = g.createRadialGradient(220, 860, 0, 220, 860, 620);
      warm.addColorStop(0, "rgba(255, 122, 69, 0.78)");
      warm.addColorStop(1, "rgba(255, 122, 69, 0)");
      g.fillStyle = warm;
      g.fillRect(0, 0, W, W);

      // Cool cyber-ice radial glow on top-right (cyber cobalt/ice)
      const cool = g.createRadialGradient(820, 180, 0, 820, 180, 640);
      cool.addColorStop(0, "rgba(61, 123, 255, 0.82)");
      cool.addColorStop(1, "rgba(61, 123, 255, 0)");
      g.fillStyle = cool;
      g.fillRect(0, 0, W, W);

      // Bold display typography refracted through the glass
      const currentText = stateRef.current.text || "CITADEL";
      const face = '900 100px "Big Shoulders Display", Impact, "Arial Narrow", sans-serif';
      g.font = face;
      const measured = g.measureText(currentText).width;
      const fs = Math.min((W * 0.86) / (measured || 100) * 100, W * 0.84 / 0.86);
      g.font = face.replace("100px", `${Math.round(fs)}px`);
      g.fillStyle = "#f3efe8";
      g.textAlign = "center";
      g.textBaseline = "middle";
      g.fillText(currentText, W / 2, W / 2 + fs * 0.03);

      uploadPlate();
    };

    plateDrawerRef.current = drawPlate;

    function compile(type: number, src: string) {
      if (!gl) throw new Error("No WebGL context");
      const s = gl.createShader(type);
      if (!s) throw new Error("Shader creation failed");
      gl.shaderSource(s, src);
      gl.compileShader(s);
      if (!gl.getShaderParameter(s, gl.COMPILE_STATUS)) {
        const info = gl.getShaderInfoLog(s);
        gl.deleteShader(s);
        throw new Error(info || "Compilation failed");
      }
      return s;
    }

    let prog: WebGLProgram | null = null;
    let buf: WebGLBuffer | null = null;
    const U: Record<string, WebGLUniformLocation | null> = {};

    try {
      prog = gl.createProgram();
      if (!prog) throw new Error("Program creation failed");
      const vs = compile(gl.VERTEX_SHADER, VS);
      const fs = compile(gl.FRAGMENT_SHADER, FS);
      gl.attachShader(prog, vs);
      gl.attachShader(prog, fs);
      gl.linkProgram(prog);
      if (!gl.getProgramParameter(prog, gl.LINK_STATUS)) {
        throw new Error(gl.getProgramInfoLog(prog) || "Link error");
      }
      gl.useProgram(prog);

      buf = gl.createBuffer();
      gl.bindBuffer(gl.ARRAY_BUFFER, buf);
      gl.bufferData(
        gl.ARRAY_BUFFER,
        new Float32Array([-1, -1, 3, -1, -1, 3]),
        gl.STATIC_DRAW
      );

      const loc = gl.getAttribLocation(prog, "aPos");
      gl.enableVertexAttribArray(loc);
      gl.vertexAttribPointer(loc, 2, gl.FLOAT, false, 0, 0);

      [
        "uRes",
        "uRot",
        "uOff",
        "uSize",
        "uDepth",
        "uChroma",
        "uFrost",
        "uTint",
        "uShape",
        "uPlate",
      ].forEach((n) => {
        if (prog && gl) U[n] = gl.getUniformLocation(prog, n);
      });

      tex = gl.createTexture();
      gl.bindTexture(gl.TEXTURE_2D, tex);
      gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_MIN_FILTER, gl.LINEAR);
      gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_MAG_FILTER, gl.LINEAR);
      gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_WRAP_S, gl.CLAMP_TO_EDGE);
      gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_WRAP_T, gl.CLAMP_TO_EDGE);
      if (U.uPlate) gl.uniform1i(U.uPlate, 0);
    } catch (e) {
      console.warn("WebGL initialization encountered an error:", e);
      setWebglFailed(true);
      return;
    }

    // Resize viewport
    const resize = () => {
      if (!gl || !cv) return;
      const dpr = Math.min(window.devicePixelRatio || 1, 2);
      const px = Math.max(64, Math.min(1200, Math.round(cv.clientWidth * dpr)));
      if (cv.width !== px || cv.height !== px) {
        cv.width = cv.height = px;
      }
      gl.viewport(0, 0, cv.width, cv.height);
    };

    let resizeObserver: ResizeObserver | null = null;
    if (window.ResizeObserver) {
      resizeObserver = new ResizeObserver(resize);
      resizeObserver.observe(cv);
    } else {
      window.addEventListener("resize", resize);
    }

    // Pointer drag-to-orient
    let dragYaw = 0;
    let dragPitch = 0;
    let dragging = false;
    let lx = 0;
    let ly = 0;

    const onPointerDown = (e: PointerEvent) => {
      dragging = true;
      lx = e.clientX;
      ly = e.clientY;
      try {
        cv.setPointerCapture(e.pointerId);
      } catch {
        /* ignore */
      }
    };

    const onPointerMove = (e: PointerEvent) => {
      if (!dragging) return;
      dragYaw += (e.clientX - lx) * 0.01;
      dragPitch += (e.clientY - ly) * 0.01;
      lx = e.clientX;
      ly = e.clientY;
    };

    const onPointerUp = () => {
      dragging = false;
    };

    cv.addEventListener("pointerdown", onPointerDown);
    cv.addEventListener("pointermove", onPointerMove);
    cv.addEventListener("pointerup", onPointerUp);
    cv.addEventListener("pointercancel", onPointerUp);

    // Reduced motion check
    const motionQuery = window.matchMedia("(prefers-reduced-motion: reduce)");
    stateRef.current.reducedMotion = motionQuery.matches;
    const onMotionChange = (e: MediaQueryListEvent) => {
      stateRef.current.reducedMotion = e.matches;
    };
    motionQuery.addEventListener?.("change", onMotionChange);

    // Animation loop with floating bobbing movement
    let visible = true;
    let running = false;
    let spin = 0;
    let t = 0;
    let last = performance.now();
    let raf = 0;

    const frame = (now: number) => {
      if (!visible || !gl || !cv) {
        running = false;
        return;
      }
      const dt = Math.min(0.05, (now - last) / 1000);
      last = now;
      t += dt;

      const currentSpeed = stateRef.current.reducedMotion ? 0 : stateRef.current.speed;
      spin += dt * currentSpeed * 0.5;

      // Floating bobbing motion on pitch and vertical translation:
      const bobPitch = Math.sin(t * 0.6) * 0.2 * Math.min(currentSpeed, 1) + dragPitch;
      const bobVertical = 0.05 * Math.sin(t * 1.1);

      const R = mul3(Ry(spin + dragYaw), Rx(bobPitch));

      gl.uniform2f(U.uRes, cv.width, cv.height);
      gl.uniformMatrix3fv(U.uRot, false, R);
      gl.uniform2f(U.uOff, 0, bobVertical);
      gl.uniform1f(U.uSize, stateRef.current.size);
      gl.uniform1f(U.uDepth, stateRef.current.depth);
      gl.uniform1f(U.uChroma, stateRef.current.chromatic);
      gl.uniform1f(U.uFrost, stateRef.current.frost);
      gl.uniform3fv(U.uTint, stateRef.current.tint);
      gl.uniform1i(U.uShape, stateRef.current.shape);

      gl.drawArrays(gl.TRIANGLES, 0, 3);
      raf = requestAnimationFrame(frame);
    };

    const start = () => {
      if (!running) {
        running = true;
        last = performance.now();
        raf = requestAnimationFrame(frame);
      }
    };

    let intersectionObserver: IntersectionObserver | null = null;
    if (window.IntersectionObserver) {
      intersectionObserver = new IntersectionObserver((entries) => {
        visible = entries[0]?.isIntersecting ?? true;
        if (visible) start();
      });
      intersectionObserver.observe(cv);
    }

    drawPlate();
    if (document.fonts && document.fonts.load) {
      document.fonts.load('900 100px "Big Shoulders Display"').then(drawPlate).catch(() => {});
    }
    resize();
    start();

    return () => {
      cancelAnimationFrame(raf);
      if (resizeObserver) resizeObserver.disconnect();
      else window.removeEventListener("resize", resize);
      if (intersectionObserver) intersectionObserver.disconnect();
      motionQuery.removeEventListener?.("change", onMotionChange);
      cv.removeEventListener("pointerdown", onPointerDown);
      cv.removeEventListener("pointermove", onPointerMove);
      cv.removeEventListener("pointerup", onPointerUp);
      cv.removeEventListener("pointercancel", onPointerUp);
      if (gl) {
        if (tex) gl.deleteTexture(tex);
        if (buf) gl.deleteBuffer(buf);
        if (prog) gl.deleteProgram(prog);
      }
    };
  }, []);

  return (
    <div
      ref={containerRef}
      className={`floating-glass-stage ${className}`}
      style={{
        position: "relative",
        width: "100%",
        aspectRatio: "1",
        borderRadius: 14,
        overflow: "hidden",
        background: "#07090e",
        border: "1px solid rgba(255, 255, 255, 0.12)",
        boxShadow: "0 24px 60px rgba(0, 0, 0, 0.6), inset 0 1px 0 rgba(255, 255, 255, 0.1)",
        ...style,
      }}
    >
      <canvas
        ref={canvasRef}
        style={{
          display: "block",
          width: "100%",
          height: "100%",
          cursor: "grab",
          touchAction: "pan-y",
        }}
        aria-label="Real-time floating glass torus refracting CITADEL"
      />
      {webglFailed && (
        <div
          style={{
            position: "absolute",
            inset: 0,
            display: "grid",
            placeItems: "center",
            padding: 24,
            textAlign: "center",
            color: "var(--muted)",
          }}
        >
          <p>WebGL is unavailable. The 3D glass torus is running in 2D CSS fallback mode.</p>
        </div>
      )}
    </div>
  );
}

/* ==========================================================================
   Liquid glass cluster — GPU shader
   A raymarched cluster of three glass solids with refraction, dispersion,
   frosted scattering, studio softbox reflections and fresnel rims.
   ========================================================================== */

export const GLASS_VERT = `
attribute vec2 aPos;
void main() {
  gl_Position = vec4(aPos, 0.0, 1.0);
}
`;

export const GLASS_FRAG = `
precision highp float;

uniform vec2  uRes;
uniform float uTime;
uniform vec2  uPointer;
uniform mat3  uInvRot;
uniform vec2  uOffset;
uniform float uFit;
uniform float uDepth;
uniform vec3  uTint;
uniform float uChroma;
uniform float uFrost;
uniform int   uShape;
uniform float uTanHalf;
uniform sampler2D uBackdrop;
uniform float uHasBackdrop;
uniform sampler2D uEnv;
uniform sampler2D uLogo;
uniform float uHasLogo;

/* camera ray, assigned in main and read by the shading helpers */
vec3 rd;

const float CAM_DIST = 5.0;
const float PLANE_Z  = -3.4;
const float PI       = 3.14159265359;

/* ---------- rotation ---------------------------------------------------- */

vec3 rotX(vec3 p, float a) {
  float c = cos(a), s = sin(a);
  return mat3(1.0, 0.0, 0.0, 0.0, c, -s, 0.0, s, c) * p;
}

vec3 rotY(vec3 p, float a) {
  float c = cos(a), s = sin(a);
  return mat3(c, 0.0, -s, 0.0, 1.0, 0.0, s, 0.0, c) * p;
}

vec3 rotZ(vec3 p, float a) {
  float c = cos(a), s = sin(a);
  return mat3(c, s, 0.0, -s, c, 0.0, 0.0, 0.0, 1.0) * p;
}

/* ---------- hashing ----------------------------------------------------- */

float hash21(vec2 p) {
  p = fract(p * vec2(123.34, 456.21));
  p += dot(p, p + 45.32);
  return fract(p.x * p.y);
}

/* ---------- signed distance fields -------------------------------------- */

float sdRoundBox(vec3 p, vec3 b, float r) {
  vec3 q = abs(p) - b;
  return length(max(q, 0.0)) + min(max(q.x, max(q.y, q.z)), 0.0) - r;
}

float smin(float a, float b, float k) {
  float h = clamp(0.5 + 0.5 * (b - a) / k, 0.0, 1.0);
  return mix(b, a, h) - k * h * (1.0 - h);
}

float sdBar(vec3 p, float angle) {
  float c = cos(angle), s = sin(angle);
  vec3 q = p;
  q.xy = mat2(c, -s, s, c) * q.xy;
  return sdRoundBox(q, vec3(0.82, 0.23, 0.30), 0.11);
}

float sdShape(vec3 p, int kind) {
  if (kind == 1) {
    return length(p) - 0.92;
  }
  if (kind == 2) {
    vec2 q = vec2(length(p.xz) - 0.62, p.y);
    return length(q) - 0.28;
  }
  if (kind == 3) {
    return sdRoundBox(p, vec3(0.94, 0.72, 0.30), 0.16);
  }
  return smin(sdBar(p, 0.785398), sdBar(p, -0.785398), 0.06);
}

/* ---------- the cluster ------------------------------------------------- */

float bodyA(vec3 p) {
  vec3 q = p - vec3(-1.16, 0.60, -0.42);
  q = rotZ(q, 0.16);
  q = rotY(q, 0.50);
  q = rotX(q, 0.26);
  q /= 0.52;
  return sdShape(q, uShape) * 0.52;
}

float bodyB(vec3 p) {
  vec3 q = p - vec3(1.22, 0.74, -0.55);
  q = rotZ(q, -0.24);
  q = rotY(q, -0.66);
  q = rotX(q, -0.18);
  q /= 0.41;
  return sdShape(q, uShape) * 0.41;
}

float bodyC(vec3 p) {
  vec3 q = p - vec3(0.02, -0.68, 0.02);
  q = rotZ(q, 0.10);
  q = rotY(q, 0.22);
  q = rotX(q, 0.14);
  q /= 0.80;
  return sdShape(q, uShape) * 0.80;
}

float mapScene(vec3 p) {
  vec3 q = uInvRot * (p - vec3(uOffset, 0.0));
  q /= uFit;
  float d = min(min(bodyA(q), bodyB(q)), bodyC(q)) * uFit;
  return d;
}

int nearestBody(vec3 p) {
  vec3 q = uInvRot * (p - vec3(uOffset, 0.0));
  q /= uFit;
  float a = bodyA(q);
  float b = bodyB(q);
  float c = bodyC(q);
  if (a <= b && a <= c) return 0;
  if (b <= c) return 1;
  return 2;
}

float bodyScale(int id) {
  if (id == 0) return 0.52;
  if (id == 1) return 0.41;
  return 0.80;
}

/* ---------- lighting environment --------------------------------------- */

float band(float x, float center, float halfWidth, float softness) {
  return smoothstep(center - halfWidth - softness, center - halfWidth + softness, x) *
         (1.0 - smoothstep(center + halfWidth - softness, center + halfWidth + softness, x));
}

vec3 envMap(vec3 d) {
  vec3 base = mix(vec3(0.027, 0.012, 0.020), vec3(0.12, 0.04, 0.08),
                  smoothstep(-0.55, 0.9, d.y));
  float az = atan(d.x, d.z) + uPointer.x * 0.16;
  float el = asin(clamp(d.y, -1.0, 1.0));

  float key   = band(az, -0.92, 0.40, 0.13) * band(el, 0.60, 0.20, 0.10);
  float fill  = band(az,  1.38, 0.26, 0.14) * band(el, 0.26, 0.17, 0.11);
  float strip = band(az,  0.08, 0.85, 0.25) * band(el, 0.97, 0.05, 0.14);
  float warm  = band(az,  2.70, 0.22, 0.16) * band(el, -0.18, 0.10, 0.14);

  vec3 col = base;
  col += key   * vec3(2.10, 1.95, 1.70);
  col += fill  * vec3(0.68, 0.17, 0.33) * 0.95;
  col += strip * vec3(0.61, 0.67, 0.59) * 0.55;
  col += warm  * vec3(0.87, 0.73, 0.54) * 0.40;
  return col;
}

/* ---------- refracted background --------------------------------------- */

vec3 bg(vec2 p) {
  float aspect = uRes.x / uRes.y;
  vec3 col = mix(vec3(0.027, 0.012, 0.020), vec3(0.086, 0.039, 0.070),
                 smoothstep(-1.1, 1.1, p.y));

  col += vec3(0.68, 0.17, 0.33) * 0.35 *
         exp(-length(p - vec2(-0.86, 0.46)) * 1.15);
  col += vec3(0.61, 0.67, 0.59) * 0.24 *
         exp(-length(p - vec2(1.02, -0.20)) * 1.20);
  col += vec3(0.87, 0.73, 0.54) * 0.18 *
         exp(-length(p - vec2(0.18, -0.94)) * 1.60);

  /* a long soft light ribbon, used to reveal the refraction */
  float ribbon = smoothstep(0.30, 0.0, abs(p.y + 0.22 - sin(p.x * 2.2) * 0.06));
  col += vec3(0.97, 0.95, 0.91) * ribbon * 0.055;

  float ring = abs(length(p - vec2(-0.08, 0.10)) - 1.18);
  col += vec3(0.68, 0.17, 0.33) * smoothstep(0.012, 0.0, ring) * 0.20;

  float specks = smoothstep(0.9965, 1.0, hash21(floor(p * 54.0)));
  col += vec3(0.97, 0.95, 0.91) * specks * 0.45;

  /* the prepared studio plate adds believable light behind the glass */
  vec2 euv = p / vec2(aspect, 1.0) * 0.5 + 0.5;
  col += texture2D(uEnv, clamp(euv, 0.0, 1.0)).rgb * 0.10;

  if (uHasBackdrop > 0.5) {
    vec2 buv = p / vec2(aspect, 1.0) * 0.5 + 0.5;
    vec3 plate = texture2D(uBackdrop, clamp(buv, 0.002, 0.998)).rgb;
    col = mix(col, plate, 0.86);
  }
  return col;
}

vec2 projectPoint(vec3 p) {
  float z = max(CAM_DIST - p.z, 0.35);
  return (p.xy * CAM_DIST / z) / uTanHalf;
}

vec3 refractSample(vec3 pos, vec3 n, float ior, float thickness, float blur) {
  vec3 r = refract(-rd, n, 1.0 / ior);
  if (dot(r, r) < 0.001) r = reflect(-rd, n);

  float denom = min(r.z, -0.10);
  float tp = (PLANE_Z - pos.z) / denom;
  tp = clamp(tp, 0.0, 14.0);
  vec3 exitP = pos + r * tp + n * thickness * 0.16;
  vec2 base = projectPoint(exitP);
  base = clamp(base, vec2(-2.6), vec2(2.6));

  vec2 jitter = vec2(0.0);
  float a = hash21(gl_FragCoord.xy + uTime * 0.03) * 6.2831;
  jitter = vec2(cos(a), sin(a)) * (0.004 + blur * 0.10);

  vec3 c = bg(base) * 0.52;
  c += bg(base + jitter) * 0.16;
  c += bg(base - jitter * 0.7) * 0.16;
  c += bg(base + vec2(jitter.y, -jitter.x) * 0.5) * 0.16;
  return c;
}

/* ---------- glass shading ---------------------------------------------- */

vec3 shadeGlass(vec3 pos, vec3 n, int body) {
  vec3 v = -rd;
  float ndv = clamp(dot(n, v), 0.0, 1.0);
  float fres = pow(1.0 - ndv, 5.0);

  float thick = (0.16 + 0.22 * uDepth) * (0.65 + bodyScale(body));
  float iorBase = 1.5;

  vec3 refr;
  refr.r = refractSample(pos, n, iorBase - uChroma * 0.055, thick, uFrost).r;
  refr.g = refractSample(pos, n, iorBase, thick, uFrost).g;
  refr.b = refractSample(pos, n, iorBase + uChroma * 0.055, thick, uFrost).b;

  vec3 tint = uTint;
  vec3 col = refr * mix(vec3(1.0), tint, 0.24);

  vec3 env = envMap(reflect(rd, n));
  col += env * (0.16 + 0.85 * fres);

  /* broad internal glow toward the center of the mass */
  col += tint * 0.035;

  /* thin bright fresnel edge */
  float rim = pow(1.0 - ndv, 3.2);
  col += mix(tint, vec3(0.97, 0.95, 0.91), 0.5) * rim * 0.48;

  /* laser-bright specular glints from the softboxes */
  vec3 l1 = normalize(vec3(-0.55, 0.78, 0.62));
  vec3 l2 = normalize(vec3(0.72, 0.18, 0.55));
  float s1 = pow(max(dot(reflect(rd, n), l1), 0.0), 92.0);
  float s2 = pow(max(dot(reflect(rd, n), l2), 0.0), 140.0);
  col += vec3(1.0, 0.99, 0.96) * s1 * 1.9;
  col += vec3(0.61, 0.67, 0.59) * s2 * 1.2;

  /* a faint etched logo, only for the logo shape */
  if (uShape == 3 && uHasLogo > 0.5) {
    vec3 lp = uInvRot * (pos - vec3(uOffset, 0.0)) / max(uFit, 0.001);
    vec2 luv = lp.xy * 0.52 + 0.5;
    if (luv.x > 0.0 && luv.x < 1.0 && luv.y > 0.0 && luv.y < 1.0) {
      float mark = texture2D(uLogo, luv).a;
      col = mix(col, tint * 0.16 + vec3(0.04, 0.015, 0.03), mark * 0.82);
      col += vec3(0.68, 0.17, 0.33) * smoothstep(0.55, 0.0, mark) * mark * 0.35;
    }
  }

  return col;
}

vec3 calcNormal(vec3 p) {
  const float e = 0.0035;
  return normalize(vec3(
    mapScene(p + vec3(e, 0.0, 0.0)) - mapScene(p - vec3(e, 0.0, 0.0)),
    mapScene(p + vec3(0.0, e, 0.0)) - mapScene(p - vec3(0.0, e, 0.0)),
    mapScene(p + vec3(0.0, 0.0, e)) - mapScene(p - vec3(0.0, 0.0, e))
  ));
}

void main() {
  vec2 p = (gl_FragCoord.xy * 2.0 - uRes) / uRes.y;
  float aspect = uRes.x / uRes.y;

  vec3 ro = vec3(0.0, 0.0, CAM_DIST);
  rd = normalize(vec3(p * uTanHalf, -1.0));

  vec3 center = vec3(uOffset, 0.0);
  float radius = 2.55;
  vec3 oc = ro - center;
  float b = dot(oc, rd);
  float c = dot(oc, oc) - radius * radius;
  float disc = b * b - c;

  bool covered = false;
  float minD = 100.0;
  vec3 hitPos = vec3(0.0);

  if (disc > 0.0) {
    float tEnter = max(0.0, -b - sqrt(disc));
    float tExit = -b + sqrt(disc);
    float t = tEnter;
    for (int i = 0; i < 84; i++) {
      vec3 pos = ro + rd * t;
      float d = mapScene(pos);
      minD = min(minD, d);
      if (d < 0.0016) {
        covered = true;
        hitPos = pos;
        break;
      }
      t += max(d, 0.0015);
      if (t > tExit) break;
    }
  }

  vec3 glassCol = vec3(0.0);
  float cover = 0.0;

  if (covered) {
    vec3 n = calcNormal(hitPos);
    int body = nearestBody(hitPos);
    glassCol = shadeGlass(hitPos, n, body);
    cover = 1.0;
  } else if (minD < 0.05) {
    cover = smoothstep(0.05, 0.0, minD) * 0.55;
    glassCol = vec3(0.68, 0.17, 0.33) * 0.9;
  }

  /* a whisper of ambient light around the cluster */
  vec2 ap = p - vec2(uOffset.x, -0.06);
  float aura = exp(-length(ap * vec2(0.62, 1.0)) * 2.35) * 0.085;
  aura *= (1.0 - cover);

  float alpha = clamp(cover + aura, 0.0, 1.0);
  vec3 finalCol = mix(vec3(0.68, 0.17, 0.33), glassCol, cover);
  finalCol = mix(finalCol, vec3(0.61, 0.67, 0.59), aura * 1.6);

  gl_FragColor = vec4(finalCol, alpha);
}
`;

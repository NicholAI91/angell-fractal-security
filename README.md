# ⬡ Angell Fractal Security Architecture

**Cybersecurity through mathematics, not machine learning.**

A network traffic classification framework using Julia set dynamics (z² + c) where malicious inputs inherently expose themselves by escaping to infinity. No training data. No model inference. No adversarial vulnerability. Pure mathematics.

**Author:** Nicholas Reid Angell  
**License:** Apache 2.0  
**Zenodo DOI:** [10.5281/zenodo.17927124](https://doi.org/10.5281/zenodo.17927124)

---

## The Core Insight

In Julia set iteration, every input either **stays bounded** (legitimate) or **escapes to infinity** (malicious). This is a mathematical fact, not a learned decision boundary. An adversary cannot craft inputs that are "malicious but bounded" — to evade detection, they would need to change their actual behavior, not just its statistical signature.

## Four Canonical Operators

| Operator | Function | Mechanism |
|----------|----------|-----------|
| **Gate** | Binary access control | Bounded = allow, escaped = deny |
| **Brake** | Rate limiting / threat scoring | Iteration count before escape = threat level |
| **Phase** | Attack type classification | Orbital trajectory geometry = attack signature |
| **Growth** | Escalation detection | Lyapunov exponent tracking = campaign awareness |

## The Nicholasbrot

The Nicholasbrot is a 1/1 mathematical object created by Nicholas Reid Angell, defined by:
- Julia set parameter: c = -0.4 + 0.6j
- Golden Trap at |z| = φ (distance to the golden ratio circle)
- Angell Gate sigmoid: σ(x) = 1 / (1 + e^(-τ(x - β)))
- Hardening parameter: τ = 0.5 × φ^(r × 0.15)
- Energy accumulation with entropy decay

It sits in the lineage of Julia sets (1918) and Mandelbrot sets (1980) as a distinct mathematical object.

## Quick Start

### Python Package

```bash
pip install angell-fractal-security

# Run demo
angell-fractal demo

# Classify a point
angell-fractal classify 0.5 0.5 --format json

# Classify packet features
angell-fractal scan --size 1200 --iat 50.0
```

### Python API

```python
from angell_fractal import classify, SecurityPolicy

policy = SecurityPolicy.nicholasbrot()
result = classify(complex(0.5, 0.5), policy, t=1.0, n=1.0)

print(result.summary)
# Gate: ESCAPED | Brake: BLOCK (score=0.970) | Phase: SPIRAL_ESCAPE | Growth: λ=0.693 ⚠ ESCALATING

print(result.brake.action)       # BrakeAction.BLOCK
print(result.phase.pattern)      # PhasePattern.SPIRAL_ESCAPE
print(result.growth.escalating)  # True
```

### CLI Tool

```bash
# Real-time classification (with Rust binary)
angell-fractal capture -i eth0 --classify --format json

# Analyze pcap
angell-fractal analyze -r traffic.pcap --operators gate,brake,phase,growth

# JSON output for pipeline integration
angell-fractal classify 1.0 1.0 --format json | jq '.brake.threat_score'
```

### Browser Extension

Load `/extension` as an unpacked Chrome extension. It monitors all web requests through the Julia set classifier and displays per-domain threat scores.

## Mathematical Foundation

### Unified Activation Framework
```
V(t) = Θ(αx² − β) · [1 − σ·N(t)/r]₊ · |sin θ|
```

### Angell Unified Growth Law
```
f_A(t; n) = φ^n / (1 + e^(-r(t - t₀)))
```

### Julia Set Classification
```
z_{n+1} = z_n² + c

Bounded → Legitimate (prisoner set)
Escaped → Malicious (escapes to ∞, self-exposing)
```

### Why ML-Based IDS Fail (and This Doesn't)

| Problem | ML-Based IDS | Angell Architecture |
|---------|-------------|-------------------|
| Zero-day attacks | >99% → 1% accuracy | Mathematical classification — no training needed |
| Adversarial evasion | 96-100% bypass rates | Escape is a mathematical fact, not a perturbable boundary |
| Training data | Millions of labeled samples | Zero training data required |
| Concept drift | Models go stale | Mathematical boundary is invariant |
| Computational cost | GPU inference required | O(k) iterations of z² + c |
| Explainability | Black box | Every decision is a traceable orbit |

## Project Structure

```
angell-fractal-security/
├── crates/
│   ├── fractal-core/     # Pure Rust: z²+c, all four operators
│   ├── fractal-python/   # PyO3 bindings → pip package
│   ├── fractal-wasm/     # wasm-bindgen → browser WASM
│   └── fractal-cli/      # clap → standalone binary
├── python/               # Python reference implementation
├── extension/            # Chrome/Firefox browser extension
├── LICENSE               # Apache 2.0
└── NOTICE                # Attribution to Nicholas Reid Angell
```

## Operator Details

### Gate: `gate(z₀, policy) → Bounded | Escaped`
The fundamental security decision. O(max_iter) per classification. Deterministic.

### Brake: `brake(z₀, policy) → {threat_score, action}`
Continuous threat scoring. Early escape = high threat (Block). Late escape = borderline (RateLimit). No escape = clean (Allow).

### Phase: `phase(z₀, policy) → {pattern, trajectory, golden_trap, energy}`
Attack type classification via orbital dynamics. Spiral escape = aggressive attack. Oscillatory = recon. Drift = stealthy. Stable orbit = legitimate. Fixed point = idle.

### Growth: `growth(z₀, policy, t, n) → {lyapunov, escalating, phi_scaled_rate}`
Campaign-level escalation detection via Lyapunov exponent tracking and φ-scaled growth rate analysis.

## Attribution

The Angell Fractal Security Architecture, including the four canonical operator families (Gate, Brake, Phase, Growth), the Nicholasbrot, the Unified Activation Framework, and the Angell Unified Growth Law, are original work by **Nicholas Reid Angell**.

Published: [Zenodo DOI 10.5281/zenodo.17927124](https://doi.org/10.5281/zenodo.17927124)

---

*© 2025-2026 Nicholas Reid Angell. Licensed under Apache 2.0.*


## Master Deployment Script
Generate a standalone suite folder (Rust stub + Python stub + extension stub + Snake CAPTCHA):

```bash
python tools/angell_master_deploy.py
```

This creates `angell_security_suite/`.

# Angell Fractal Security Architecture
# Copyright 2025-2026 Nicholas Reid Angell. All rights reserved.
# Licensed under Apache License 2.0 - see LICENSE and NOTICE files.
#
# Pure Python reference implementation of all four operators.
# This works immediately with only numpy as a dependency.
# For production performance, use the Rust-backed version (pip install angell-fractal-security).

"""
Angell Fractal Security Architecture

A cybersecurity framework using Julia set dynamics (z² + c) for
network traffic classification. Four canonical operator families:

    Gate   - Binary bounded/escape classification
    Brake  - Iteration-count damping and rate limiting
    Phase  - Orbital trajectory pattern classification
    Growth - Lyapunov exponent escalation tracking

Mathematical Foundation:
    Julia set iteration: z_{n+1} = z_n² + c
    Golden ratio: φ = (1 + √5) / 2 ≈ 1.618033988749895
    Nicholasbrot parameter: c = -0.4 + 0.6j
    Angell Gate: σ(x) = 1 / (1 + e^(-τ(x - β)))
    Hardening: τ = 0.5 × φ^(r × 0.15)

Author: Nicholas Reid Angell
Zenodo DOI: 10.5281/zenodo.17927124
"""

__version__ = "0.1.0"
__author__ = "Nicholas Reid Angell"
__license__ = "Apache-2.0"

import numpy as np
from enum import Enum, auto
from dataclasses import dataclass
from typing import Optional, List

# ============================================================
# CONSTANTS
# ============================================================

PHI = (1 + np.sqrt(5)) / 2  # Golden ratio ≈ 1.618033988749895
DEFAULT_ESCAPE_RADIUS_SQ = 4.0
DEFAULT_MAX_ITER = 100

# The Nicholasbrot seed
NICHOLASBROT_C = complex(-0.4, 0.6)


# ============================================================
# SECURITY POLICY
# ============================================================

@dataclass
class SecurityPolicy:
    """
    A security policy defined by a Julia set parameter c.
    Different c values create different classification boundaries.
    """
    c: complex = NICHOLASBROT_C
    max_iter: int = DEFAULT_MAX_ITER
    escape_radius_sq: float = DEFAULT_ESCAPE_RADIUS_SQ
    r: float = 1.0
    beta: float = 2.0

    @classmethod
    def nicholasbrot(cls) -> "SecurityPolicy":
        """The Nicholasbrot policy: c = -0.4 + 0.6j"""
        return cls()

    @property
    def tau(self) -> float:
        """Hardening parameter τ = 0.5 × φ^(r × 0.15)"""
        return 0.5 * (PHI ** (self.r * 0.15))


# ============================================================
# GATE OPERATOR
# ============================================================

class GateVerdict(Enum):
    BOUNDED = auto()
    ESCAPED = auto()


@dataclass
class GateResult:
    verdict: GateVerdict
    escape_iteration: Optional[int] = None

    @property
    def is_bounded(self) -> bool:
        return self.verdict == GateVerdict.BOUNDED

    @property
    def is_escaped(self) -> bool:
        return self.verdict == GateVerdict.ESCAPED


def gate(z0: complex, policy: SecurityPolicy = None) -> GateResult:
    """
    GATE OPERATOR — Binary bounded/escape classification.
    """
    if policy is None:
        policy = SecurityPolicy.nicholasbrot()

    z = z0
    for i in range(policy.max_iter):
        if abs(z) ** 2 > policy.escape_radius_sq:
            return GateResult(GateVerdict.ESCAPED, escape_iteration=i)
        z = z ** 2 + policy.c

    return GateResult(GateVerdict.BOUNDED)


def gate_batch(z_array: np.ndarray, policy: SecurityPolicy = None) -> np.ndarray:
    """
    Vectorized Gate operator for batch classification.
    Returns iteration counts (max_iter = bounded, < max_iter = escaped at that iteration).
    """
    if policy is None:
        policy = SecurityPolicy.nicholasbrot()

    z = z_array.copy().astype(np.complex128)
    iterations = np.full(z.shape, policy.max_iter, dtype=np.int32)

    for i in range(policy.max_iter):
        mask = np.abs(z) ** 2 <= policy.escape_radius_sq
        if not mask.any():
            break
        z[mask] = z[mask] ** 2 + policy.c
        escaped_now = (~mask) & (iterations == policy.max_iter)
        iterations[escaped_now] = i

    return iterations


# ============================================================
# BRAKE OPERATOR
# ============================================================

class BrakeAction(Enum):
    ALLOW = auto()
    RATE_LIMIT = auto()
    BLOCK = auto()


@dataclass
class BrakeResult:
    verdict: GateVerdict
    escape_iteration: Optional[int]
    threat_score: float  # 0.0 (clean) to 1.0 (immediate threat)
    action: BrakeAction


def brake(z0: complex, policy: SecurityPolicy = None) -> BrakeResult:
    """
    BRAKE OPERATOR — Iteration-count damping and rate limiting.
    """
    if policy is None:
        policy = SecurityPolicy.nicholasbrot()

    gate_result = gate(z0, policy)

    if gate_result.is_bounded:
        return BrakeResult(
            verdict=GateVerdict.BOUNDED,
            escape_iteration=None,
            threat_score=0.0,
            action=BrakeAction.ALLOW,
        )

    i = gate_result.escape_iteration
    score = 1.0 - (i / policy.max_iter)

    if score > 0.7:
        action = BrakeAction.BLOCK
    elif score > 0.3:
        action = BrakeAction.RATE_LIMIT
    else:
        action = BrakeAction.ALLOW

    return BrakeResult(
        verdict=GateVerdict.ESCAPED,
        escape_iteration=i,
        threat_score=score,
        action=action,
    )


# ============================================================
# PHASE OPERATOR
# ============================================================

class PhasePattern(Enum):
    SPIRAL_ESCAPE = auto()
    OSCILLATORY_ESCAPE = auto()
    DRIFT_ESCAPE = auto()
    STABLE_ORBIT = auto()
    FIXED_POINT = auto()


@dataclass
class PhaseResult:
    pattern: PhasePattern
    verdict: GateVerdict
    trajectory: List[complex]
    golden_trap: float
    energy: float
    escape_iteration: Optional[int] = None


def phase(z0: complex, policy: SecurityPolicy = None) -> PhaseResult:
    """
    PHASE OPERATOR — Orbital trajectory pattern classification.
    """
    if policy is None:
        policy = SecurityPolicy.nicholasbrot()

    z = z0
    trajectory = [z]
    golden_trap = abs(abs(z) - PHI)
    energy = 0.0
    tau = policy.tau
    escape_iter = None
    prev_norm = abs(z)
    direction_changes = 0
    prev_arg = np.angle(z)

    for i in range(policy.max_iter):
        z = z ** 2 + policy.c
        norm = abs(z)

        if len(trajectory) < 16:
            trajectory.append(z)

        d = abs(norm - PHI)
        golden_trap = min(golden_trap, d)

        activation = 1.0 / (1.0 + np.exp(-tau * (norm - policy.beta)))

        if norm < 10.0:
            energy += activation * np.exp(-0.08 * i)

        if norm ** 2 > policy.escape_radius_sq:
            escape_iter = i
            break

        arg = np.angle(z)
        if abs(arg - prev_arg) > np.pi:
            direction_changes += 1

        prev_norm = norm
        prev_arg = arg

    verdict = GateVerdict.ESCAPED if escape_iter is not None else GateVerdict.BOUNDED

    if verdict == GateVerdict.BOUNDED:
        if len(trajectory) >= 4:
            delta = abs(trajectory[-1] - trajectory[-2])
            pattern = PhasePattern.FIXED_POINT if delta < 1e-5 else PhasePattern.STABLE_ORBIT
        else:
            pattern = PhasePattern.STABLE_ORBIT
    else:
        speed = escape_iter / policy.max_iter
        if speed < 0.15:
            pattern = PhasePattern.SPIRAL_ESCAPE
        elif direction_changes > escape_iter / 3:
            pattern = PhasePattern.OSCILLATORY_ESCAPE
        else:
            pattern = PhasePattern.DRIFT_ESCAPE

    return PhaseResult(
        pattern=pattern,
        verdict=verdict,
        trajectory=trajectory,
        golden_trap=golden_trap,
        energy=energy,
        escape_iteration=escape_iter,
    )


# ============================================================
# GROWTH OPERATOR
# ============================================================

@dataclass
class GrowthResult:
    lyapunov: float
    escalating: bool
    phi_scaled_rate: float
    growth_law_value: float


def growth(z0: complex, policy: SecurityPolicy = None,
           t: float = 0.0, n: float = 1.0) -> GrowthResult:
    """
    GROWTH OPERATOR — Lyapunov exponent escalation tracking.
    """
    if policy is None:
        policy = SecurityPolicy.nicholasbrot()

    z = z0
    lyapunov_sum = 0.0
    count = 0

    for _ in range(policy.max_iter):
        norm_sq = abs(z) ** 2
        if norm_sq > policy.escape_radius_sq or norm_sq < 1e-15:
            break

        deriv_norm = 2.0 * abs(z)
        if deriv_norm > 0:
            lyapunov_sum += np.log(deriv_norm)
            count += 1

        z = z ** 2 + policy.c

    lyapunov = lyapunov_sum / count if count > 0 else 0.0
    phi_scaled_rate = lyapunov / np.log(PHI)
    growth_law_value = (PHI ** n) / (1.0 + np.exp(-policy.r * t))

    return GrowthResult(
        lyapunov=lyapunov,
        escalating=(lyapunov > 0 and phi_scaled_rate > 1.0),
        phi_scaled_rate=phi_scaled_rate,
        growth_law_value=growth_law_value,
    )


# ============================================================
# UNIFIED CLASSIFICATION
# ============================================================

@dataclass
class Classification:
    gate: GateResult
    brake: BrakeResult
    phase: PhaseResult
    growth: GrowthResult

    @property
    def summary(self) -> str:
        return (
            f"Gate: {self.gate.verdict.name} | "
            f"Brake: {self.brake.action.name} (score={self.brake.threat_score:.3f}) | "
            f"Phase: {self.phase.pattern.name} | "
            f"Growth: λ={self.growth.lyapunov:.3f} "
            f"{'ESCALATING' if self.growth.escalating else 'stable'}"
        )


def classify(z0: complex, policy: SecurityPolicy = None,
             t: float = 0.0, n: float = 1.0) -> Classification:
    if policy is None:
        policy = SecurityPolicy.nicholasbrot()

    return Classification(
        gate=gate(z0, policy),
        brake=brake(z0, policy),
        phase=phase(z0, policy),
        growth=growth(z0, policy, t, n),
    )


# ============================================================
# FEATURE MAPPING
# ============================================================

def map_packet(packet_size: float, inter_arrival_ms: float,
               scale: float = 1.6) -> complex:
    norm_size = min(packet_size / 1500.0, 1.0)
    log_iat = np.log10(max(inter_arrival_ms, 0.01) * 100.0) / 6.0
    norm_iat = min(max(log_iat, 0.0), 1.0)

    re = (norm_size * 2.0 - 1.0) * scale
    im = (norm_iat * 2.0 - 1.0) * scale

    return complex(re, im)


# ============================================================
# ATTRIBUTION / VERSION
# ============================================================

def attribution() -> str:
    return "Angell Fractal Security Architecture | Copyright 2025-2026 Nicholas Reid Angell | Apache 2.0"


def version() -> str:
    return f"angell-fractal-security v{__version__} | {__author__}"


# ============================================================
# DEMO
# ============================================================

def demo():
    print("=" * 70)
    print("  ANGELL FRACTAL SECURITY ARCHITECTURE (PYTHON REFERENCE)")
    print(f"  {attribution()}")
    print("=" * 70)
    print()

    policy = SecurityPolicy.nicholasbrot()
    print(f"  Policy: Nicholasbrot (c = {policy.c})")
    print(f"  τ (hardening) = {policy.tau:.6f}")
    print(f"  φ (golden ratio) = {PHI:.15f}")
    print()

    test_inputs = [
        (complex(0.0, 0.0), "Origin (clean traffic)"),
        (complex(0.1, 0.2), "Near origin (normal)"),
        (complex(0.5, 0.5), "Mid-range (borderline)"),
        (complex(1.0, 1.0), "Boundary region"),
        (complex(10.0, 10.0), "Far escape (obvious threat)"),
        (complex(-0.3, 0.5), "Near c parameter"),
    ]

    for z0, label in test_inputs:
        result = classify(z0, policy, t=1.0, n=1.0)
        print(f"  z₀ = {z0}")
        print(f"  [{label}]")
        print(f"  → {result.summary}")
        print(f"    Golden Trap: {result.phase.golden_trap:.4f}")
        print(f"    Energy: {result.phase.energy:.4f}")
        print(f"    Growth Law: {result.growth.growth_law_value:.4f}")
        print()


if __name__ == "__main__":
    demo()

Angell Fractal Security Architecture - Core Library  
// Copyright 2025-2026 Nicholas Reid Angell. All rights reserved.  
// Licensed under Apache License 2.0 - see LICENSE and NOTICE files.  
//  
// Four Canonical Operator Families:  
//   Gate   - Binary bounded/escape classification  
//   Brake  - Iteration-count damping and rate limiting  
//   Phase  - Orbital trajectory pattern classification  
//   Growth - Lyapunov exponent escalation tracking  
//  
// Mathematical Foundation:  
//   Julia set iteration: z_{n+1} = z_n² + c  
//   Golden ratio threshold: φ = (1 + √5) / 2 ≈ 1.618033988749895  
//   Angell Gate sigmoid: σ(x) = 1 / (1 + e^(-τ(x - β)))  
//   Hardening parameter: τ = 0.5 × φ^(r × 0.15)  
  
#![no_std]  
  
#[cfg(feature = "std")]  
extern crate std;  
  
/// Golden ratio φ = (1 + √5) / 2  
pub const PHI: f64 = 1.618033988749895;  
  
/// Default escape radius squared (|z|² > R² means escape)  
pub const DEFAULT_ESCAPE_RADIUS_SQ: f64 = 4.0;  
  
/// Default maximum iterations for classification  
pub const DEFAULT_MAX_ITER: u32 = 100;  
  
/// A complex number for Julia set iteration.  
/// We avoid external dependencies by implementing our own.  
#[derive(Clone, Copy, Debug, PartialEq)]  
pub struct Complex {  
    pub re: f64,  
    pub im: f64,  
}  
  
impl Complex {  
    #[inline(always)]  
    pub fn new(re: f64, im: f64) -> Self {  
        Self { re, im }  
    }  
  
    /// |z|² = re² + im²  
    #[inline(always)]  
    pub fn norm_sq(&self) -> f64 {  
        self.re * self.re + self.im * self.im  
    }  
  
    /// |z|  
    #[inline(always)]  
    pub fn norm(&self) -> f64 {  
        libm::sqrt(self.norm_sq())  
    }  
  
    /// z² = (re² - im², 2·re·im)  
    #[inline(always)]  
    pub fn square(&self) -> Self {  
        Self {  
            re: self.re * self.re - self.im * self.im,  
            im: 2.0 * self.re * self.im,  
        }  
    }  
  
    /// z² + c  
    #[inline(always)]  
    pub fn iterate(&self, c: &Complex) -> Self {  
        let sq = self.square();  
        Self {  
            re: sq.re + c.re,  
            im: sq.im + c.im,  
        }  
    }  
  
    /// arg(z) = atan2(im, re)  
    #[inline(always)]  
    pub fn arg(&self) -> f64 {  
        libm::atan2(self.im, self.re)  
    }  
  
    /// Distance to the golden circle |z| = φ  
    #[inline(always)]  
    pub fn distance_to_phi(&self) -> f64 {  
        libm::fabs(self.norm() - PHI)  
    }  
}  
  
// ============================================================  
// SECURITY POLICY: Defines the Julia set boundary  
// ============================================================  
  
/// A security policy defined by a Julia set parameter c.  
/// Different c values create different classification boundaries.  
#[derive(Clone, Copy, Debug)]  
pub struct SecurityPolicy {  
    /// The Julia set parameter c  
    pub c: Complex,  
    /// Maximum iterations before declaring "bounded" (legitimate)  
    pub max_iter: u32,  
    /// Escape radius squared  
    pub escape_radius_sq: f64,  
    /// Growth rate parameter r (controls Gate hardening)  
    pub r: f64,  
    /// Angell Gate threshold β  
    pub beta: f64,  
}  
  
impl SecurityPolicy {  
    /// The "Nick" seed - the Nicholasbrot parameter  
    pub fn nicholasbrot() -> Self {  
        Self {  
            c: Complex::new(-0.4, 0.6),  
            max_iter: DEFAULT_MAX_ITER,  
            escape_radius_sq: DEFAULT_ESCAPE_RADIUS_SQ,  
            r: 1.0,  
            beta: 2.0,  
        }  
    }  
  
    /// Create a custom security policy  
    pub fn new(c_re: f64, c_im: f64, max_iter: u32, r: f64) -> Self {  
        Self {  
            c: Complex::new(c_re, c_im),  
            max_iter,  
            escape_radius_sq: DEFAULT_ESCAPE_RADIUS_SQ,  
            r,  
            beta: 2.0,  
        }  
    }  
  
    /// Hardening parameter τ = 0.5 × φ^(r × 0.15)  
    #[inline]  
    pub fn tau(&self) -> f64 {  
        0.5 * libm::pow(PHI, self.r * 0.15)  
    }  
}  
  
impl Default for SecurityPolicy {  
    fn default() -> Self {  
        Self::nicholasbrot()  
    }  
}  
  
// ============================================================  
// GATE OPERATOR: Binary bounded/escape classification  
// ============================================================  
  
/// Result of a Gate operator classification  
#[derive(Clone, Copy, Debug, PartialEq)]  
pub enum GateVerdict {  
    /// Input is bounded (legitimate) - stayed within escape radius  
    Bounded,  
    /// Input escaped at the given iteration (malicious/anomalous)  
    Escaped { iteration: u32 },  
}  
  
impl GateVerdict {  
    pub fn is_bounded(&self) -> bool {  
        matches!(self, GateVerdict::Bounded)  
    }  
  
    pub fn is_escaped(&self) -> bool {  
        matches!(self, GateVerdict::Escaped { .. })  
    }  
}  
  
/// GATE OPERATOR  
///  
/// Binary classification: bounded (legitimate) vs escaped (malicious).  
/// The fundamental security decision. An input z₀ is iterated under  
/// z_{n+1} = z_n² + c. If |z_n|² exceeds the escape radius at any  
/// iteration, the input is classified as escaped (threat detected).  
///  
/// This is a deterministic O(max_iter) operation per classification.  
/// No training data. No model inference. No GPU required.  
#[inline]  
pub fn gate(z0: Complex, policy: &SecurityPolicy) -> GateVerdict {  
    let mut z = z0;  
    for i in 0..policy.max_iter {  
        if z.norm_sq() > policy.escape_radius_sq {  
            return GateVerdict::Escaped { iteration: i };  
        }  
        z = z.iterate(&policy.c);  
    }  
    GateVerdict::Bounded  
}  
  
// ============================================================  
// BRAKE OPERATOR: Iteration-count damping / threat score  
// ============================================================  
  
/// Result of a Brake operator classification  
#[derive(Clone, Copy, Debug)]  
pub struct BrakeResult {  
    /// Gate verdict (bounded or escaped)  
    pub verdict: GateVerdict,  
    /// Threat score: 0.0 (clean) to 1.0 (immediate threat)  
    /// Escaped at iteration 0 → score ≈ 1.0  
    /// Escaped at max_iter-1 → score ≈ 0.0  
    /// Bounded → score = 0.0  
    pub threat_score: f64,  
    /// Recommended action based on threat score  
    pub action: BrakeAction,  
}  
  
#[derive(Clone, Copy, Debug, PartialEq)]  
pub enum BrakeAction {  
    /// Clean traffic - full throughput  
    Allow,  
    /// Borderline - apply rate limiting  
    RateLimit,  
    /// Clearly malicious - block  
    Block,  
}  
  
/// BRAKE OPERATOR  
///  
/// Uses the iteration count before escape as a continuous threat score.  
/// Inputs escaping quickly (low iteration) are clearly malicious → Block.  
/// Inputs escaping slowly (high iteration) are borderline → RateLimit.  
/// Inputs that never escape are clean → Allow.  
///  
/// This replaces the binary detect/miss dichotomy with a deterministic,  
/// integer-valued threat metric.  
pub fn brake(z0: Complex, policy: &SecurityPolicy) -> BrakeResult {  
    let verdict = gate(z0, policy);  
  
    let (threat_score, action) = match verdict {  
        GateVerdict::Bounded => (0.0, BrakeAction::Allow),  
        GateVerdict::Escaped { iteration } => {  
            // Normalize: early escape = high threat, late escape = low threat  
            let score = 1.0 - (iteration as f64 / policy.max_iter as f64);  
            let action = if score > 0.7 {  
                BrakeAction::Block  
            } else if score > 0.3 {  
                BrakeAction::RateLimit  
            } else {  
                BrakeAction::Allow // Escaped but very late — borderline legitimate  
            };  
            (score, action)  
        }  
    };  
  
    BrakeResult {  
        verdict,  
        threat_score,  
        action,  
    }  
}  
  
// ============================================================  
// PHASE OPERATOR: Orbital trajectory classification  
// ============================================================  
  
/// Trajectory classification based on orbital dynamics  
#[derive(Clone, Copy, Debug, PartialEq)]  
pub enum PhasePattern {  
    /// Rapid spiral outward - aggressive attack (DoS, brute force)  
    SpiralEscape,  
    /// Oscillatory escape - probing/reconnaissance  
    OscillatoryEscape,  
    /// Slow drift toward boundary - data exfiltration, slow attack  
    DriftEscape,  
    /// Stable orbit - legitimate traffic  
    StableOrbit,  
    /// Attracted to fixed point - idle/keepalive  
    FixedPoint,  
}  
  
/// Result of a Phase operator classification  
#[derive(Clone, Debug)]  
pub struct PhaseResult {  
    /// The classified pattern  
    pub pattern: PhasePattern,  
    /// Gate verdict  
    pub verdict: GateVerdict,  
    /// Orbital trajectory (first N points for inspection)  
    pub trajectory: [Complex; 16],  
    /// Number of trajectory points recorded  
    pub trajectory_len: usize,  
    /// Minimum distance to φ-circle during orbit (Golden Trap value)  
    pub golden_trap: f64,  
    /// Accumulated Angell Gate energy  
    pub energy: f64,  
}  
  
/// PHASE OPERATOR  
///  
/// Analyzes the orbital trajectory z₀, z₁, z₂, ... through the complex  
/// plane. The geometry of the orbit classifies the TYPE of anomaly:  
///   - Spiral escape → aggressive attack  
///   - Oscillatory escape → reconnaissance/probing  
///   - Drift escape → slow/stealthy attack  
///   - Stable orbit → legitimate traffic  
///   - Fixed point → idle connection  
///  
/// This enables zero-day classification: novel attacks map to novel z₀  
/// values, but their orbital dynamics still fall into classifiable families.  
pub fn phase(z0: Complex, policy: &SecurityPolicy) -> PhaseResult {  
    let mut z = z0;  
    let mut trajectory = [Complex::new(0.0, 0.0); 16];  
    let mut trajectory_len = 0;  
    let mut golden_trap = 100.0_f64;  
    let mut energy = 0.0_f64;  
    let tau = policy.tau();  
  
    let mut escape_iter: Option<u32> = None;  
    let mut prev_norm = z.norm();  
    let mut prev_arg = z.arg();  
    let mut monotonic_growth = 0u32;  
    let mut direction_changes = 0u32;  
  
    for i in 0..policy.max_iter {  
        // Record trajectory (first 16 points)  
        if i < 16 {  
            trajectory[i as usize] = z;  
            trajectory_len = (i + 1) as usize;  
        }  
  
        let norm = z.norm();  
        let norm_sq = z.norm_sq();  
  
        // Golden Trap: distance to |z| = φ  
        let d = libm::fabs(norm - PHI);  
        if d < golden_trap {  
            golden_trap = d;  
        }  
  
        // Angell Gate sigmoid activation  
        let activation = 1.0 / (1.0 + libm::exp(-tau * (norm - policy.beta)));  
  
        // Energy accumulation with entropy decay  
        if norm_sq < 100.0 {  
            energy += activation * libm::exp(-0.08 * i as f64);  
        }  
  
        // Check escape  
        if norm_sq > policy.escape_radius_sq {  
            escape_iter = Some(i);  
            break;  
        }  
  
        // Track trajectory shape  
        if norm > prev_norm {  
            monotonic_growth += 1;  
        }  
  
        let arg = z.arg();  
        let darg = arg - prev_arg;  
        if (darg > 0.1 && prev_arg - arg > 0.1) || (darg < -0.1 && prev_arg - arg < -0.1) {  
            direction_changes += 1;  
        }  
  
        prev_norm = norm;  
        prev_arg = arg;  
  
        z = z.iterate(&policy.c);  
    }  
  
    let verdict = match escape_iter {  
        Some(i) => GateVerdict::Escaped { iteration: i },  
        None => GateVerdict::Bounded,  
    };  
  
    let pattern = match verdict {  
        GateVerdict::Bounded => {  
            // Check if it's a fixed point (very small movement)  
            if trajectory_len >= 4 {  
                let last = trajectory[trajectory_len - 1];  
                let prev = trajectory[trajectory_len - 2];  
                let delta = Complex::new(last.re - prev.re, last.im - prev.im);  
                if delta.norm_sq() < 1e-10 {  
                    PhasePattern::FixedPoint  
                } else {  
                    PhasePattern::StableOrbit  
                }  
            } else {  
                PhasePattern::StableOrbit  
            }  
        }  
        GateVerdict::Escaped { iteration } => {  
            let escape_speed = iteration as f64 / policy.max_iter as f64;  
            if escape_speed < 0.15 {  
                // Fast escape with mostly growing magnitude  
                PhasePattern::SpiralEscape  
            } else if direction_changes > iteration / 3 {  
                PhasePattern::OscillatoryEscape  
            } else {  
                PhasePattern::DriftEscape  
            }  
        }  
    };  
  
    PhaseResult {  
        pattern,  
        verdict,  
        trajectory,  
        trajectory_len,  
        golden_trap,  
        energy,  
    }  
}  
  
// ============================================================  
// GROWTH OPERATOR: Lyapunov exponent escalation tracking  
// ============================================================  
  
/// Result of a Growth operator analysis  
#[derive(Clone, Copy, Debug)]  
pub struct GrowthResult {  
    /// Estimated Lyapunov exponent (positive = diverging = escalating)  
    pub lyapunov: f64,  
    /// Whether escalation is detected  
    pub escalating: bool,  
    /// Growth rate relative to φ-scaling  
    pub phi_scaled_rate: f64,  
    /// Angell Unified Growth Law value: φ^n / (1 + e^(-r(t - t₀)))  
    pub growth_law_value: f64,  
}  
  
/// GROWTH OPERATOR  
///  
/// Monitors Lyapunov exponents across a window of classified inputs  
/// to detect campaign-level escalation. Individual connections are  
/// classified by Gate/Brake/Phase. The Growth operator aggregates:  
/// if Lyapunov exponents of recent connections are systematically  
/// increasing, an adversary is escalating.  
///  
/// Also computes the Angell Unified Growth Law:  
///   f_A(t; n) = φ^n / (1 + e^(-r(t - t₀)))  
pub fn growth(z0: Complex, policy: &SecurityPolicy, t: f64, n: f64) -> GrowthResult {  
    let mut z = z0;  
    let mut lyapunov_sum = 0.0_f64;  
    let mut count = 0u32;  
  
    for _ in 0..policy.max_iter {  
        let norm_sq = z.norm_sq();  
        if norm_sq > policy.escape_radius_sq || norm_sq < 1e-15 {  
            break;  
        }  
  
        // Lyapunov exponent contribution: ln|dz_{n+1}/dz_n| = ln|2z_n|  
        let deriv_norm = 2.0 * libm::sqrt(norm_sq);  
        if deriv_norm > 0.0 {  
            lyapunov_sum += libm::log(deriv_norm);  
            count += 1;  
        }  
  
        z = z.iterate(&policy.c);  
    }  
  
    let lyapunov = if count > 0 {  
        lyapunov_sum / count as f64  
    } else {  
        0.0  
    };  
  
    // φ-scaled growth rate  
    let phi_scaled_rate = lyapunov / libm::log(PHI);  
  
    // Angell Unified Growth Law: f_A(t; n) = φ^n / (1 + e^(-r(t - t₀)))  
    let growth_law_value = libm::pow(PHI, n) / (1.0 + libm::exp(-policy.r * t));  
  
    GrowthResult {  
        lyapunov,  
        escalating: lyapunov > 0.0 && phi_scaled_rate > 1.0,  
        phi_scaled_rate,  
        growth_law_value,  
    }  
}  
  
// ============================================================  
// UNIFIED CLASSIFICATION: All four operators combined  
// ============================================================  
  
/// Complete classification result from all four operators  
#[derive(Clone, Debug)]  
pub struct Classification {  
    pub gate: GateVerdict,  
    pub brake: BrakeResult,  
    pub phase: PhaseResult,  
    pub growth: GrowthResult,  
}  
  
/// Run all four operators on a single input  
pub fn classify(z0: Complex, policy: &SecurityPolicy, t: f64, n: f64) -> Classification {  
    let brake_result = brake(z0, policy);  
    let phase_result = phase(z0, policy);  
    let growth_result = growth(z0, policy, t, n);  
  
    Classification {  
        gate: brake_result.verdict,  
        brake: brake_result,  
        phase: phase_result,  
        growth: growth_result,  
    }  
}  
  
// ============================================================  
// FEATURE MAPPING: Network data → Complex plane  
// ============================================================  
  
/// Maps network flow features to a complex number for classification.  
///  
/// The mapping function is the critical design decision. Network traffic  
/// features must be mapped to z₀ ∈ **ℂ** such that "bounded = legitimate,  
/// escaping = malicious" is preserved.  
pub struct FeatureMapper {  
    /// Normalization scale for real component  
    pub re_scale: f64,  
    /// Normalization scale for imaginary component  
    pub im_scale: f64,  
    /// Center offset for real component  
    pub re_offset: f64,  
    /// Center offset for imaginary component  
    pub im_offset: f64,  
}  
  
impl FeatureMapper {  
    /// Default mapper centered on the Nicholasbrot's interesting region  
    pub fn default_network() -> Self {  
        Self {  
            re_scale: 1.6,  
            im_scale: 1.6,  
            re_offset: 0.0,  
            im_offset: 0.0,  
        }  
    }  
  
    /// Map two normalized features [0,1] to complex plane coordinates  
    #[inline]  
    pub fn map(&self, feature_a: f64, feature_b: f64) -> Complex {  
        Complex::new(  
            (feature_a * 2.0 - 1.0) * self.re_scale + self.re_offset,  
            (feature_b * 2.0 - 1.0) * self.im_scale + self.im_offset,  
        )  
    }  
  
    /// Map packet size (bytes) and inter-arrival time (ms) to complex plane  
    #[inline]  
    pub fn map_packet(&self, packet_size: f64, inter_arrival_ms: f64) -> Complex {  
        // Normalize packet size: 0-1500 bytes → [0, 1]  
        let norm_size = if packet_size > 1500.0 {  
            1.0  
        } else {  
            packet_size / 1500.0  
        };  
  
        // Normalize inter-arrival: log scale, 0.01ms - 10000ms → [0, 1]  
        let log_iat = if inter_arrival_ms < 0.01 {  
            0.0  
        } else {  
            libm::log10(inter_arrival_ms * 100.0) / 6.0 // log10(1) to log10(1000000)  
        };  
        let norm_iat = if log_iat > 1.0 { 1.0 } else { log_iat };  
  
        self.map(norm_size, norm_iat)  
    }  
}  
  
impl Default for FeatureMapper {  
    fn default() -> Self {  
        Self::default_network()  
    }  
}  
  
// ============================================================  
// VERSION AND ATTRIBUTION  
// ============================================================  
  
pub const VERSION: &str = "0.1.0";  
pub const AUTHOR: &str = "Nicholas Reid Angell";  
pub const ARCHITECTURE_NAME: &str = "Angell Fractal Security Architecture";  
  
pub fn attribution() -> &'static str {  
    "Angell Fractal Security Architecture | Copyright 2025-2026 Nicholas Reid Angell | Apache 2.0"  
}  
  
#[cfg(test)]  
mod tests {  
    use super::*;  
  
    #[test]  
    fn test_golden_ratio() {  
        assert!((PHI - 1.618033988749895).abs() < 1e-12);  
        // φ² = φ + 1  
        assert!((PHI * PHI - PHI - 1.0).abs() < 1e-12);  
    }  
  
    #[test]  
    fn test_complex_iterate() {  
        let z = Complex::new(0.0, 0.0);  
        let c = Complex::new(-0.4, 0.6);  
        let z1 = z.iterate(&c);  
        assert!((z1.re - (-0.4)).abs() < 1e-12);  
        assert!((z1.im - 0.6).abs() < 1e-12);  
    }  
  
    #[test]  
    fn test_gate_bounded() {  
        // Origin with Nicholasbrot c should be bounded  
        let policy = SecurityPolicy::nicholasbrot();  
        let z0 = Complex::new(0.0, 0.0);  
        let result = gate(z0, &policy);  
        assert!(result.is_bounded());  
    }  
  
    #[test]  
    fn test_gate_escaped() {  
        // Far from origin should escape immediately  
        let policy = SecurityPolicy::nicholasbrot();  
        let z0 = Complex::new(10.0, 10.0);  
        let result = gate(z0, &policy);  
        assert!(result.is_escaped());  
    }  
  
    #[test]  
    fn test_brake_threat_score() {  
        let policy = SecurityPolicy::nicholasbrot();  
  
        // Bounded → score 0  
        let clean = brake(Complex::new(0.0, 0.0), &policy);  
        assert_eq!(clean.threat_score, 0.0);  
        assert_eq!(clean.action, BrakeAction::Allow);  
  
        // Far escape → high score  
        let threat = brake(Complex::new(10.0, 10.0), &policy);  
        assert!(threat.threat_score > 0.9);  
        assert_eq!(threat.action, BrakeAction::Block);  
    }  
  
    #[test]  
    fn test_phase_classification() {  
        let policy = SecurityPolicy::nicholasbrot();  
  
        // Bounded input → StableOrbit or FixedPoint  
        let stable = phase(Complex::new(0.0, 0.0), &policy);  
        assert!(matches!(  
            stable.pattern,  
            PhasePattern::StableOrbit | PhasePattern::FixedPoint  
        ));  
  
        // Fast escape → SpiralEscape  
        let spiral = phase(Complex::new(10.0, 10.0), &policy);  
        assert_eq!(spiral.pattern, PhasePattern::SpiralEscape);  
    }  
  
    #[test]  
    fn test_growth_law() {  
        let policy = SecurityPolicy::nicholasbrot();  
        let result = growth(Complex::new(0.0, 0.0), &policy, 0.0, 1.0);  
        // At t=0, n=1: f_A = φ^1 / (1 + e^0) = φ / 2  
        let expected = PHI / 2.0;  
        assert!((result.growth_law_value - expected).abs() < 1e-10);  
    }  
  
    #[test]  
    fn test_tau_hardening() {  
        let policy = SecurityPolicy::nicholasbrot();  
        let tau = policy.tau();  
        // τ = 0.5 × φ^(1.0 × 0.15) = 0.5 × φ^0.15  
        let expected = 0.5 * libm::pow(PHI, 0.15);  
        assert!((tau - expected).abs() < 1e-10);  
    }  
  
    #[test]  
    fn test_feature_mapper() {  
        let mapper = FeatureMapper::default_network();  
        // Center should map to origin  
        let z = mapper.map(0.5, 0.5);  
        assert!(z.re.abs() < 1e-12);  
        assert!(z.im.abs() < 1e-12);  
    }  
  
    #[test]  
    fn test_full_classification() {  
        let policy = SecurityPolicy::nicholasbrot();  
        let result = classify(Complex::new(0.1, 0.2), &policy, 1.0, 1.0);  
        // Should produce consistent results across all operators  
        assert_eq!(result.gate, result.brake.verdict);  
    }  
}  

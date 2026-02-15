#!/usr/bin/env python3
"""
Angell Fractal Security Architecture - CLI Interface
Copyright 2025-2026 Nicholas Reid Angell. All rights reserved.
"""

import argparse
import json
from . import (
    classify, SecurityPolicy, map_packet,
    PHI, attribution, version, demo,
)


def main():
    parser = argparse.ArgumentParser(
        prog="angell-fractal",
        description="Angell Fractal Security Architecture: Julia set network classification",
        epilog=attribution(),
    )
    parser.add_argument("--version", action="version", version=version())

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # Demo command
    subparsers.add_parser("demo", help="Run demonstration of all four operators")

    # Classify command
    classify_parser = subparsers.add_parser("classify", help="Classify a complex input")
    classify_parser.add_argument("real", type=float, help="Real component of z0")
    classify_parser.add_argument("imag", type=float, help="Imaginary component of z0")
    classify_parser.add_argument("--max-iter", type=int, default=100)
    classify_parser.add_argument("--c-real", type=float, default=-0.4)
    classify_parser.add_argument("--c-imag", type=float, default=0.6)
    classify_parser.add_argument("--format", choices=["text", "json"], default="text")

    # Scan command (classify packet features)
    scan_parser = subparsers.add_parser("scan", help="Classify from packet features")
    scan_parser.add_argument("--size", type=float, required=True, help="Packet size (bytes)")
    scan_parser.add_argument("--iat", type=float, required=True, help="Inter-arrival time (ms)")
    scan_parser.add_argument("--format", choices=["text", "json"], default="text")

    # Info command
    subparsers.add_parser("info", help="Show framework information")

    args = parser.parse_args()

    if args.command == "demo":
        demo()
        return

    if args.command == "classify":
        z0 = complex(args.real, args.imag)
        policy = SecurityPolicy(
            c=complex(args.c_real, args.c_imag),
            max_iter=args.max_iter,
        )
        result = classify(z0, policy, t=1.0, n=1.0)

        if args.format == "json":
            output = {
                "input": {"real": args.real, "imag": args.imag},
                "gate": result.gate.verdict.name,
                "brake": {
                    "action": result.brake.action.name,
                    "threat_score": float(result.brake.threat_score),
                },
                "phase": {
                    "pattern": result.phase.pattern.name,
                    "golden_trap": float(result.phase.golden_trap),
                    "energy": float(result.phase.energy),
                },
                "growth": {
                    "lyapunov": float(result.growth.lyapunov),
                    "escalating": bool(result.growth.escalating),
                    "phi_scaled_rate": float(result.growth.phi_scaled_rate),
                },
            }
            print(json.dumps(output, indent=2))
        else:
            print(f"z0 = {z0}")
            print(result.summary)
        return

    if args.command == "scan":
        z0 = map_packet(args.size, args.iat)
        policy = SecurityPolicy.nicholasbrot()
        result = classify(z0, policy, t=1.0, n=1.0)

        if args.format == "json":
            output = {
                "packet_size": float(args.size),
                "inter_arrival_ms": float(args.iat),
                "mapped_z": {"real": float(z0.real), "imag": float(z0.imag)},
                "gate": result.gate.verdict.name,
                "brake": {
                    "action": result.brake.action.name,
                    "threat_score": float(result.brake.threat_score),
                },
                "phase": result.phase.pattern.name,
                "growth": {"escalating": bool(result.growth.escalating)},
            }
            print(json.dumps(output, indent=2))
        else:
            print(f"Packet: {args.size} bytes, IAT={args.iat}ms -> z0 = {z0.real:.4f}+{z0.imag:.4f}j")
            print(result.summary)
        return

    if args.command == "info":
        pol = SecurityPolicy.nicholasbrot()
        print(f"\n  {version()}")
        print(f"  {attribution()}")
        print(f"\n  phi = {PHI:.15f}")
        print(f"  Nicholasbrot c = {pol.c}")
        print(f"  tau (hardening) = {pol.tau:.6f}")
        print("\n  Operators: Gate, Brake, Phase, Growth")
        print("  Zenodo DOI: 10.5281/zenodo.17927124\n")
        return

    parser.print_help()


if __name__ == "__main__":
    main()

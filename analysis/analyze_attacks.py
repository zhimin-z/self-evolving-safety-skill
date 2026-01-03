#!/usr/bin/env python3
"""
Comprehensive attack results analysis tool.
Combines comparison, detailed analysis, and visualization.

Usage:
    # Quick summary comparison
    python analysis/analyze_attacks.py --summary
    
    # Detailed index-by-index comparison
    python analysis/analyze_attacks.py --detailed
    
    # Quick visualization
    python analysis/analyze_attacks.py --viz
    
    # All analysis types
    python analysis/analyze_attacks.py --all
"""

import argparse
import json
import os
from collections import defaultdict


# ============================================================================
# Data Loading Functions
# ============================================================================

def load_baseline_results(results_dir):
    """Load baseline results from individual JSON files"""
    baseline_results = []
    json_files = sorted([f for f in os.listdir(results_dir) if f.endswith('.json')])
    
    for json_file in json_files:
        file_path = os.path.join(results_dir, json_file)
        with open(file_path, 'r') as f:
            data = json.load(f)
            if isinstance(data, list):
                baseline_results.extend(data)
            else:
                baseline_results.append(data)
    
    return baseline_results


def load_evolved_results(results_dir):
    """Load evolved results from either consolidated file (old) or separate files (new)"""
    evolved_agent_dir = os.path.join(results_dir, 'astropy__astropy-13977')
    
    # Check if we have the old consolidated format
    old_consolidated = os.path.join(evolved_agent_dir, '2025-12-08_02:24:19.398306.json')
    if os.path.exists(old_consolidated):
        # Old format: single consolidated file
        with open(old_consolidated, 'r') as f:
            return json.load(f)
    
    # New format: separate files like baseline
    evolved_results = []
    json_files = sorted([f for f in os.listdir(evolved_agent_dir) if f.endswith('.json')])
    
    for json_file in json_files:
        file_path = os.path.join(evolved_agent_dir, json_file)
        with open(file_path, 'r') as f:
            data = json.load(f)
            if isinstance(data, list):
                evolved_results.extend(data)
            else:
                evolved_results.append(data)
    
    return evolved_results


# ============================================================================
# Analysis Functions
# ============================================================================

def compute_attack_scores(result_data):
    """Compute attack success scores from a result entry"""
    final_result = result_data['Final Result']
    
    scores = {}
    for attack_type in ['Code', 'Code w/ jb', 'Summary', 'Details']:
        if attack_type in final_result:
            attack_results = final_result[attack_type]
            total = sum(attack_results.values())
            success = attack_results.get('3', 0)
            partial = attack_results.get('1', 0)
            fail = attack_results.get('0', 0)
            
            scores[attack_type] = {
                'total': total,
                'success': success,
                'partial': partial,
                'fail': fail,
                'success_rate': success / total if total > 0 else 0,
                'anything_rate': (success + partial) / total if total > 0 else 0
            }
    
    return scores


def aggregate_results(all_results):
    """Aggregate all results to compute overall statistics"""
    aggregated = defaultdict(lambda: {
        'total': 0,
        'success': 0,
        'partial': 0,
        'fail': 0
    })
    
    for result in all_results:
        scores = compute_attack_scores(result)
        for attack_type, metrics in scores.items():
            aggregated[attack_type]['total'] += metrics['total']
            aggregated[attack_type]['success'] += metrics['success']
            aggregated[attack_type]['partial'] += metrics['partial']
            aggregated[attack_type]['fail'] += metrics['fail']
    
    # Compute rates
    for attack_type in aggregated:
        total = aggregated[attack_type]['total']
        if total > 0:
            aggregated[attack_type]['success_rate'] = aggregated[attack_type]['success'] / total
            aggregated[attack_type]['anything_rate'] = (aggregated[attack_type]['success'] + aggregated[attack_type]['partial']) / total
    
    return aggregated


# ============================================================================
# Summary Comparison
# ============================================================================

def print_summary_comparison(baseline_results, evolved_results):
    """Print overall summary comparison"""
    print("=" * 80)
    print("ATTACK RESULTS COMPARISON: Mini-SWE-Agent vs Evolved Agent")
    print("=" * 80)
    print()
    
    baseline_agg = aggregate_results(baseline_results)
    evolved_agg = aggregate_results(evolved_results)
    
    print(f"Number of test sets:")
    print(f"  Baseline: {len(baseline_results)} test sets")
    print(f"  Evolved:  {len(evolved_results)} test sets")
    print()
    
    attack_types = ['Code', 'Code w/ jb', 'Summary', 'Details']
    
    for attack_type in attack_types:
        print(f"\n{'=' * 80}")
        print(f"Attack Type: {attack_type}")
        print('=' * 80)
        
        baseline = baseline_agg[attack_type]
        evolved = evolved_agg[attack_type]
        
        print(f"\n{'Metric':<25} {'Baseline':<20} {'Evolved':<20} {'Δ (Evolved - Baseline)':<20}")
        print('-' * 85)
        
        print(f"{'Total Attacks':<25} {baseline['total']:<20} {evolved['total']:<20} {evolved['total'] - baseline['total']:<20}")
        print(f"{'Successful (3)':<25} {baseline['success']:<20} {evolved['success']:<20} {evolved['success'] - baseline['success']:<20}")
        print(f"{'Partial (1)':<25} {baseline['partial']:<20} {evolved['partial']:<20} {evolved['partial'] - baseline['partial']:<20}")
        print(f"{'Failed (0)':<25} {baseline['fail']:<20} {evolved['fail']:<20} {evolved['fail'] - baseline['fail']:<20}")
        
        baseline_sr = baseline.get('success_rate', 0) * 100
        evolved_sr = evolved.get('success_rate', 0) * 100
        print(f"{'Success Rate':<25} {baseline_sr:<19.1f}% {evolved_sr:<19.1f}% {evolved_sr - baseline_sr:<19.1f}%")
        
        baseline_ar = baseline.get('anything_rate', 0) * 100
        evolved_ar = evolved.get('anything_rate', 0) * 100
        print(f"{'Success+Partial Rate':<25} {baseline_ar:<19.1f}% {evolved_ar:<19.1f}% {evolved_ar - baseline_ar:<19.1f}%")
    
    # Summary
    print(f"\n\n{'=' * 80}")
    print("SUMMARY")
    print('=' * 80)
    
    baseline_avg_sr = sum(baseline_agg[at].get('success_rate', 0) for at in attack_types) / len(attack_types) * 100
    evolved_avg_sr = sum(evolved_agg[at].get('success_rate', 0) for at in attack_types) / len(attack_types) * 100
    
    print(f"\nAverage Success Rate (across all attack types):")
    print(f"  Baseline: {baseline_avg_sr:.1f}%")
    print(f"  Evolved:  {evolved_avg_sr:.1f}%")
    print(f"  Improvement: {evolved_avg_sr - baseline_avg_sr:+.1f}%")
    
    baseline_total_success = sum(baseline_agg[at]['success'] for at in attack_types)
    evolved_total_success = sum(evolved_agg[at]['success'] for at in attack_types)
    baseline_total_attempts = sum(baseline_agg[at]['total'] for at in attack_types)
    evolved_total_attempts = sum(evolved_agg[at]['total'] for at in attack_types)
    
    print(f"\nTotal Successful Attacks:")
    print(f"  Baseline: {baseline_total_success}/{baseline_total_attempts} ({baseline_total_success/baseline_total_attempts*100:.1f}%)")
    print(f"  Evolved:  {evolved_total_success}/{evolved_total_attempts} ({evolved_total_success/evolved_total_attempts*100:.1f}%)")
    print(f"  Difference: {evolved_total_success - baseline_total_success:+d} attacks")


# ============================================================================
# Detailed Comparison
# ============================================================================

def print_detailed_comparison(baseline_results, evolved_results):
    """Print detailed index-by-index comparison"""
    print("=" * 100)
    print("INDEX-BY-INDEX DETAILED COMPARISON")
    print("=" * 100)
    print()
    
    baseline_sorted = sorted(baseline_results, key=lambda x: x['Index'])
    evolved_sorted = sorted(evolved_results, key=lambda x: x['Index'])
    
    print(f"{'Index':<8} {'Attack Type':<15} {'Baseline Success':<18} {'Evolved Success':<18} {'Δ':<10}")
    print('-' * 100)
    
    better_count = 0
    worse_count = 0
    same_count = 0
    
    for baseline, evolved in zip(baseline_sorted, evolved_sorted):
        idx = baseline['Index']
        
        for attack_type in ['Code', 'Code w/ jb', 'Summary', 'Details']:
            baseline_res = baseline['Final Result'].get(attack_type, {})
            evolved_res = evolved['Final Result'].get(attack_type, {})
            
            baseline_success = baseline_res.get('3', 0)
            evolved_success = evolved_res.get('3', 0)
            
            delta = evolved_success - baseline_success
            
            if delta > 0:
                delta_str = f"+{delta}"
                better_count += 1
            elif delta < 0:
                delta_str = f"{delta}"
                worse_count += 1
            else:
                delta_str = "0"
                same_count += 1
            
            baseline_total = sum(baseline_res.values())
            evolved_total = sum(evolved_res.values())
            
            baseline_str = f"{baseline_success}/{baseline_total}"
            evolved_str = f"{evolved_success}/{evolved_total}"
            
            print(f"{idx:<8} {attack_type:<15} {baseline_str:<18} {evolved_str:<18} {delta_str:<10}")
    
    print()
    print(f"Summary across all indices and attack types:")
    print(f"  Better (evolved > baseline): {better_count}")
    print(f"  Worse (evolved < baseline):  {worse_count}")
    print(f"  Same (evolved = baseline):   {same_count}")


def print_worst_performers(baseline_results, evolved_results):
    """Find indices where evolved performed significantly worse"""
    print("\n" + "=" * 100)
    print("INDICES WHERE EVOLVED PERFORMED SIGNIFICANTLY WORSE (Δ < -5)")
    print("=" * 100)
    print()
    
    baseline_sorted = sorted(baseline_results, key=lambda x: x['Index'])
    evolved_sorted = sorted(evolved_results, key=lambda x: x['Index'])
    
    worst_performers = []
    
    for baseline, evolved in zip(baseline_sorted, evolved_sorted):
        idx = baseline['Index']
        
        total_delta = 0
        for attack_type in ['Code', 'Code w/ jb', 'Summary', 'Details']:
            baseline_res = baseline['Final Result'].get(attack_type, {})
            evolved_res = evolved['Final Result'].get(attack_type, {})
            
            baseline_success = baseline_res.get('3', 0)
            evolved_success = evolved_res.get('3', 0)
            
            total_delta += (evolved_success - baseline_success)
        
        if total_delta < -5:
            worst_performers.append((idx, total_delta, baseline, evolved))
    
    worst_performers.sort(key=lambda x: x[1])
    
    if not worst_performers:
        print("No indices with significant performance degradation.")
        return
    
    for idx, delta, baseline, evolved in worst_performers:
        print(f"Index {idx}: Total delta = {delta}")
        print(f"  Baseline duration: {float(baseline.get('Duration', 0)):.1f}s")
        print(f"  Evolved duration:  {float(evolved.get('Duration', 0)):.1f}s")
        print()
        
        for attack_type in ['Code', 'Code w/ jb', 'Summary', 'Details']:
            baseline_res = baseline['Final Result'].get(attack_type, {})
            evolved_res = evolved['Final Result'].get(attack_type, {})
            
            baseline_success = baseline_res.get('3', 0)
            evolved_success = evolved_res.get('3', 0)
            
            delta_val = evolved_success - baseline_success
            
            baseline_total = sum(baseline_res.values())
            evolved_total = sum(evolved_res.values())
            
            print(f"  {attack_type:15}: Baseline {baseline_success}/{baseline_total}, Evolved {evolved_success}/{evolved_total}, Δ={delta_val:+d}")
        print()


def print_best_performers(baseline_results, evolved_results):
    """Find indices where evolved performed significantly better"""
    print("\n" + "=" * 100)
    print("INDICES WHERE EVOLVED PERFORMED SIGNIFICANTLY BETTER (Δ > +5)")
    print("=" * 100)
    print()
    
    baseline_sorted = sorted(baseline_results, key=lambda x: x['Index'])
    evolved_sorted = sorted(evolved_results, key=lambda x: x['Index'])
    
    best_performers = []
    
    for baseline, evolved in zip(baseline_sorted, evolved_sorted):
        idx = baseline['Index']
        
        total_delta = 0
        for attack_type in ['Code', 'Code w/ jb', 'Summary', 'Details']:
            baseline_res = baseline['Final Result'].get(attack_type, {})
            evolved_res = evolved['Final Result'].get(attack_type, {})
            
            baseline_success = baseline_res.get('3', 0)
            evolved_success = evolved_res.get('3', 0)
            
            total_delta += (evolved_success - baseline_success)
        
        if total_delta > 5:
            best_performers.append((idx, total_delta, baseline, evolved))
    
    best_performers.sort(key=lambda x: x[1], reverse=True)
    
    if not best_performers:
        print("No indices with significant performance improvement.")
        return
    
    for idx, delta, baseline, evolved in best_performers:
        print(f"Index {idx}: Total delta = +{delta}")
        print(f"  Baseline duration: {float(baseline.get('Duration', 0)):.1f}s")
        print(f"  Evolved duration:  {float(evolved.get('Duration', 0)):.1f}s")
        print()
        
        for attack_type in ['Code', 'Code w/ jb', 'Summary', 'Details']:
            baseline_res = baseline['Final Result'].get(attack_type, {})
            evolved_res = evolved['Final Result'].get(attack_type, {})
            
            baseline_success = baseline_res.get('3', 0)
            evolved_success = evolved_res.get('3', 0)
            
            delta_val = evolved_success - baseline_success
            
            baseline_total = sum(baseline_res.values())
            evolved_total = sum(evolved_res.values())
            
            print(f"  {attack_type:15}: Baseline {baseline_success}/{baseline_total}, Evolved {evolved_success}/{evolved_total}, Δ={delta_val:+d}")
        print()


# ============================================================================
# Visualization
# ============================================================================

def print_visualization(baseline_results, evolved_results):
    """Print quick text-based visualization"""
    baseline_agg = aggregate_results(baseline_results)
    evolved_agg = aggregate_results(evolved_results)
    
    print("\n" + "=" * 80)
    print("QUICK VISUALIZATION")
    print("=" * 80)
    print()
    print("Attack Success Rates:")
    print()
    
    attack_types = ['Code', 'Code w/ jb', 'Summary', 'Details']
    
    for attack_type in attack_types:
        baseline_rate = baseline_agg[attack_type]['success_rate'] * 100
        evolved_rate = evolved_agg[attack_type]['success_rate'] * 100
        delta = evolved_rate - baseline_rate
        
        baseline_bar = '█' * int(baseline_rate / 2)
        evolved_bar = '█' * int(evolved_rate / 2)
        
        delta_symbol = '↑' if delta > 0 else '↓' if delta < 0 else '='
        
        print(f"{attack_type:15}")
        print(f"  Baseline: {baseline_bar:<50} {baseline_rate:5.1f}%")
        print(f"  Evolved:  {evolved_bar:<50} {evolved_rate:5.1f}% {delta_symbol} {abs(delta):.1f}%")
        print()
    
    print()
    print("Overall Average Success Rate:")
    baseline_avg = sum(baseline_agg[at]['success_rate'] for at in attack_types) / len(attack_types) * 100
    evolved_avg = sum(evolved_agg[at]['success_rate'] for at in attack_types) / len(attack_types) * 100
    
    baseline_bar = '█' * int(baseline_avg / 2)
    evolved_bar = '█' * int(evolved_avg / 2)
    
    delta = evolved_avg - baseline_avg
    delta_symbol = '↑' if delta > 0 else '↓'
    
    print(f"  Baseline: {baseline_bar:<50} {baseline_avg:5.1f}%")
    print(f"  Evolved:  {evolved_bar:<50} {evolved_avg:5.1f}% {delta_symbol} {abs(delta):.1f}%")


# ============================================================================
# Main
# ============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="Analyze attack results between baseline and evolved agents"
    )
    parser.add_argument('--summary', action='store_true', help='Show summary comparison')
    parser.add_argument('--detailed', action='store_true', help='Show detailed index-by-index comparison')
    parser.add_argument('--viz', action='store_true', help='Show quick visualization')
    parser.add_argument('--all', action='store_true', help='Show all analysis types')
    
    args = parser.parse_args()
    
    # If no options specified, default to summary
    if not any([args.summary, args.detailed, args.viz, args.all]):
        args.summary = True
    
    # Load results
    baseline_dir = 'results/baseline'
    evolved_dir = 'results/evolved'
    
    print("Loading results...")
    baseline_results = load_baseline_results(baseline_dir)
    evolved_results = load_evolved_results(evolved_dir)
    print(f"✓ Loaded {len(baseline_results)} baseline and {len(evolved_results)} evolved results\n")
    
    # Run requested analyses
    if args.all or args.summary:
        print_summary_comparison(baseline_results, evolved_results)
    
    if args.all or args.viz:
        print_visualization(baseline_results, evolved_results)
    
    if args.all or args.detailed:
        print_detailed_comparison(baseline_results, evolved_results)
        print_worst_performers(baseline_results, evolved_results)
        print_best_performers(baseline_results, evolved_results)


if __name__ == '__main__':
    main()

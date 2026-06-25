"""Recommend a Terra runtime config from notebook content.

Pattern-matches the notebook source for compute signals (GPU intent,
memory-heavy genomics libraries, multiprocessing, Hail Batch) and returns
a runtime spec the agent can pass to terra_create_runtime.

Read-only. No spend. No side effects. The user (or agent) still confirms
before any `terra_create_runtime` call.

Tiers (conservative — better to over-spec than mid-run OOM):
  GPU_HEAVY    — torch + cuda install OR explicit .cuda() calls           → n1-highmem-4 + 1× T4 + 100 GB
  GPU_LIGHT    — tensorflow/jax/onnx without explicit cuda calls          → n1-highmem-4 + 1× T4 + 100 GB
  CPU_MEMORY   — scanpy / anndata / large dataframe ops                   → n1-highmem-8 + 200 GB (no GPU)
  CPU_CORES    — multiprocessing.Pool / joblib n_jobs=-1                  → n1-standard-16 + 100 GB (no GPU)
  HAIL_BATCH   — `import hail` / `hailctl batch` — driver only            → n1-standard-4 + 50 GB (the batch jobs run elsewhere)
  LIGHTWEIGHT  — pandas/sklearn/seaborn only                              → n1-standard-4 + 50 GB
  UNKNOWN      — nothing matched                                          → fallback to LIGHTWEIGHT with low confidence
"""
from __future__ import annotations

import re

# Max chars of notebook source we'll scan per cell — defeats pathological inputs.
_MAX_CELL_CHARS = 64 * 1024
_MAX_TOTAL_CHARS = 4 * 1024 * 1024


# (signal_key, compiled_regex, weight) — weights add up; tiebreakers below.
# Regexes are anchored where possible to reduce false positives.
_SIGNALS: list[tuple[str, re.Pattern[str], int]] = [
    # GPU_HEAVY (explicit CUDA intent)
    ("gpu_torch_cuda_install",
     re.compile(r"!pip install\s+torch[^\n]*\+cu\d+", re.MULTILINE), 5),
    ("gpu_torch_to_cuda",
     re.compile(r"\.(?:to|cuda)\(\s*['\"]?cuda(?::\d+)?['\"]?\s*\)"), 3),
    ("gpu_torch_device_cuda",
     re.compile(r"device\s*=\s*['\"]cuda(?::\d+)?['\"]"), 3),
    ("gpu_torch_cuda_available",
     re.compile(r"torch\.cuda\.is_available\s*\("), 2),

    # GPU_LIGHT (frameworks that often use GPU but don't always announce)
    ("gpu_tf_imported",
     re.compile(r"^import\s+tensorflow\b", re.MULTILINE), 2),
    ("gpu_jax_imported",
     re.compile(r"^import\s+jax\b", re.MULTILINE), 2),
    ("gpu_pyg_geometric",
     re.compile(r"^(?:import\s+torch_geometric|from\s+torch_geometric)\b",
                re.MULTILINE), 2),

    # CPU_MEMORY (single-cell genomics — typically multi-GB AnnData files)
    ("memory_scanpy",
     re.compile(r"^import\s+scanpy\b|^from\s+scanpy\b", re.MULTILINE), 3),
    ("memory_anndata",
     re.compile(r"^import\s+anndata\b|^from\s+anndata\b|"
                r"\b(?:sc\.read_h5ad|sc\.read_loom|ad\.read_h5ad)\("),
                3),
    ("memory_huge_h5ad",
     re.compile(r"read_h5ad\(.{0,200}\.h5ad", re.DOTALL), 2),

    # CPU_CORES (parallel CPU work)
    ("cores_multiprocessing_pool",
     re.compile(r"\bmultiprocessing\.Pool\("), 2),
    ("cores_joblib_njobs",
     re.compile(r"n_jobs\s*=\s*(?:-1|\d{2,})"), 2),
    ("cores_dask",
     re.compile(r"^import\s+dask\b|^from\s+dask\b", re.MULTILINE), 2),
    ("cores_ray",
     re.compile(r"^import\s+ray\b", re.MULTILINE), 2),

    # HAIL_BATCH (driver-only — the work runs in Hail Batch elsewhere)
    ("hail_batch",
     re.compile(r"^import\s+hail\b|^from\s+hail\b|hailctl\s+batch|hl\.Batch\b",
                re.MULTILINE), 4),
]


# Tiers (in priority order — first match wins).
# Each maps to a concrete config for terra_create_runtime.
_TIERS: list[tuple[str, set[str], dict]] = [
    ("GPU_HEAVY", {"gpu_torch_cuda_install", "gpu_torch_to_cuda",
                   "gpu_torch_device_cuda"}, {
        "machine_type": "n1-highmem-4",
        "disk_size_gb": 100,
        "gpu_type": "nvidia-tesla-t4",
        "num_gpus": 1,
        "auto_pause_threshold_minutes": 30,
        "estimated_hourly_cost_usd": 0.50,
    }),
    ("GPU_LIGHT", {"gpu_tf_imported", "gpu_jax_imported", "gpu_pyg_geometric",
                   "gpu_torch_cuda_available"}, {
        "machine_type": "n1-highmem-4",
        "disk_size_gb": 100,
        "gpu_type": "nvidia-tesla-t4",
        "num_gpus": 1,
        "auto_pause_threshold_minutes": 30,
        "estimated_hourly_cost_usd": 0.50,
    }),
    ("CPU_MEMORY", {"memory_scanpy", "memory_anndata", "memory_huge_h5ad"}, {
        "machine_type": "n1-highmem-8",
        "disk_size_gb": 200,
        "gpu_type": "",
        "num_gpus": 0,
        "auto_pause_threshold_minutes": 30,
        "estimated_hourly_cost_usd": 0.25,
    }),
    ("CPU_CORES", {"cores_multiprocessing_pool", "cores_joblib_njobs",
                   "cores_dask", "cores_ray"}, {
        "machine_type": "n1-standard-16",
        "disk_size_gb": 100,
        "gpu_type": "",
        "num_gpus": 0,
        "auto_pause_threshold_minutes": 30,
        "estimated_hourly_cost_usd": 0.40,
    }),
    ("HAIL_BATCH", {"hail_batch"}, {
        "machine_type": "n1-standard-4",
        "disk_size_gb": 50,
        "gpu_type": "",
        "num_gpus": 0,
        "auto_pause_threshold_minutes": 30,
        "estimated_hourly_cost_usd": 0.15,
    }),
]


_LIGHTWEIGHT = {
    "machine_type": "n1-standard-4",
    "disk_size_gb": 50,
    "gpu_type": "",
    "num_gpus": 0,
    "auto_pause_threshold_minutes": 30,
    "estimated_hourly_cost_usd": 0.15,
}


def analyze_source(source: str) -> dict[str, int]:
    """Return {signal_key: hit_count} for every regex that fired."""
    if not isinstance(source, str): return {}
    if len(source) > _MAX_TOTAL_CHARS:
        source = source[:_MAX_TOTAL_CHARS]
    hits: dict[str, int] = {}
    for key, pat, _w in _SIGNALS:
        n = len(pat.findall(source))
        if n: hits[key] = n
    return hits


def _collect_source_from_notebook_json(nb: dict) -> str:
    parts = []
    total = 0
    for c in nb.get("cells", []):
        if c.get("cell_type") != "code": continue
        src = c.get("source", "")
        if isinstance(src, list): src = "".join(src)
        if not isinstance(src, str): continue
        src = src[:_MAX_CELL_CHARS]
        total += len(src)
        if total > _MAX_TOTAL_CHARS:
            break
        parts.append(src)
    return "\n".join(parts)


def recommend_from_notebook_json(nb: dict, *,
                                   user_overrides: dict | None = None) -> dict:
    """Top-level entry: take a parsed .ipynb dict, return a recommendation.

    The recommendation includes:
      • machine_type, disk_size_gb, gpu_type, num_gpus,
        auto_pause_threshold_minutes, estimated_hourly_cost_usd
      • tier (one of GPU_HEAVY / GPU_LIGHT / CPU_MEMORY / CPU_CORES /
        HAIL_BATCH / LIGHTWEIGHT)
      • signals_detected: list of signal_key strings that fired
      • rationale: short human-readable list of reasons
      • confidence: 'high' | 'medium' | 'low'
      • create_runtime_args: kwargs ready to pass to terra_create_runtime

    user_overrides (optional): dict that overrides individual fields in the
    final config. Only allowed keys are the create_runtime parameters.
    """
    source = _collect_source_from_notebook_json(nb)
    hits = analyze_source(source)

    tier_name = "LIGHTWEIGHT"
    base = dict(_LIGHTWEIGHT)
    matched_keys: set[str] = set()
    for name, keys, cfg in _TIERS:
        if hits.keys() & keys:
            tier_name = name
            base = dict(cfg)
            matched_keys = hits.keys() & keys
            break

    # Rationale strings (deterministic — derived from matched signals)
    _why = {
        "gpu_torch_cuda_install": "torch+CUDA wheels in pip install",
        "gpu_torch_to_cuda":     "explicit .to('cuda') / .cuda() calls",
        "gpu_torch_device_cuda": "device='cuda' in code",
        "gpu_torch_cuda_available":"torch.cuda.is_available() check",
        "gpu_tf_imported":       "tensorflow imported",
        "gpu_jax_imported":      "jax imported",
        "gpu_pyg_geometric":     "torch_geometric imported (often GPU)",
        "memory_scanpy":         "scanpy imported (single-cell — memory-heavy)",
        "memory_anndata":        "anndata imported / read_h5ad",
        "memory_huge_h5ad":      "explicit .h5ad load — likely multi-GB",
        "cores_multiprocessing_pool": "multiprocessing.Pool — parallel CPU",
        "cores_joblib_njobs":    "joblib Parallel n_jobs=-1 — parallel CPU",
        "cores_dask":            "dask imported — parallel CPU/IO",
        "cores_ray":             "ray imported — parallel CPU",
        "hail_batch":            "Hail Batch driver (workers run elsewhere)",
    }
    rationale = [_why[k] for k in sorted(matched_keys) if k in _why]
    if not rationale:
        rationale = ["no compute signals detected — defaulting to lightweight"]

    # Confidence heuristic: more matched signals → higher confidence
    confidence = "high" if len(matched_keys) >= 2 \
                  else ("medium" if matched_keys else "low")

    # Apply caller overrides (each must be a recognised config key)
    if user_overrides:
        for k, v in user_overrides.items():
            if k in base: base[k] = v

    create_kwargs = {
        "machine_type": base["machine_type"],
        "disk_size_gb": base["disk_size_gb"],
        "gpu_type":     base["gpu_type"],
        "num_gpus":     base["num_gpus"],
        "auto_pause_threshold_minutes": base["auto_pause_threshold_minutes"],
    }
    return {
        "tier": tier_name,
        "machine_type": base["machine_type"],
        "disk_size_gb": base["disk_size_gb"],
        "gpu_type":     base["gpu_type"],
        "num_gpus":     base["num_gpus"],
        "auto_pause_threshold_minutes": base["auto_pause_threshold_minutes"],
        "estimated_hourly_cost_usd": base["estimated_hourly_cost_usd"],
        "signals_detected": sorted(hits.keys()),
        "rationale": rationale,
        "confidence": confidence,
        "create_runtime_args": create_kwargs,
        "warnings": _warnings_for(tier_name, hits),
    }


def _warnings_for(tier: str, hits: dict) -> list[str]:
    """Produce honest caveats about the recommendation."""
    w = []
    if tier.startswith("GPU"):
        w.append("GPU quota must be approved in your GCP project + zone "
                 "(check gcloud compute project-info describe). T4 is widely "
                 "available; V100/A100 often need a quota request.")
    if "gpu_torch_cuda_install" in hits:
        w.append("Cell installs CUDA-pinned torch wheels (cu118 / cu121). "
                 "Disk usage spikes ~5 GB during install — give ≥ 100 GB.")
    if tier == "CPU_MEMORY":
        w.append("highmem-8 gives ~52 GB RAM. If your AnnData is > 30 GB, "
                 "bump to n1-highmem-16 (104 GB).")
    if tier == "LIGHTWEIGHT":
        w.append("No compute signals matched. If you know the workload needs "
                 "more, override via terra_create_runtime explicitly.")
    return w

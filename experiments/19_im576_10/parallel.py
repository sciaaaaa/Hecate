"""Bounded, simultaneous-release I/O jobs. No implicit retries; all attempts persist."""
import json
import math
import threading
import time
from concurrent.futures import ThreadPoolExecutor


def percentile(values, p):
    values = sorted(values)
    return values[max(0, math.ceil(len(values)*p)-1)] if values else 0


def run_parallel(work, phase, items, operation, entity, size, resumed=False):
    items = list(items)
    if not items:
        raise ValueError('Empty parallel phase')
    started_unix = time.time()
    attempt = work/(phase+'-attempt-'+str(time.time_ns())+'.json')
    previous = list(work.glob(phase+'-attempt-*.json'))
    gate = threading.Barrier(len(items)+1, timeout=60)
    zero = [0]
    def one(item):
        gate.wait()
        start = time.perf_counter_ns()
        task = dict(entity=entity(item),start_offset_ms=(start-zero[0])/1e6,payload_bytes=size(item))
        try:
            result = operation(item)
            task['status'] = 'success'
        except Exception as exc:
            result = None
            task.update(status='failed',error=type(exc).__name__+': '+str(exc))
        task['latency_ms'] = (time.perf_counter_ns()-start)/1e6
        return result, task
    with ThreadPoolExecutor(max_workers=len(items)) as pool:
        futures = [pool.submit(one,item) for item in items]
        zero[0] = time.perf_counter_ns()
        gate.wait()
        outputs = [f.result() for f in futures]
        makespan = (time.perf_counter_ns()-zero[0])/1e6
    tasks = [task for _,task in outputs]
    good = [t for t in tasks if t['status']=='success']
    latency = [t['latency_ms'] for t in good]
    report = dict(phase=phase,started_unix=started_unix,ended_unix=time.time(),resumed=bool(resumed or previous),prior_attempts=len(previous),
        summary=dict(concurrency=len(items),submitted_count=len(items),successful_count=len(good),
            failed_count=len(items)-len(good),success_rate=len(good)/len(items),makespan_ms=makespan,
            throughput_tasks_per_s=len(good)/(makespan/1000),
            latency_sum_ms=sum(latency),latency_p50_ms=percentile(latency,.5),
            latency_p95_ms=percentile(latency,.95),latency_max_ms=max(latency,default=0),
            start_spread_ms=max(t['start_offset_ms'] for t in tasks)-min(t['start_offset_ms'] for t in tasks),
            payload_bytes=sum(t['payload_bytes'] for t in good),
            payload_goodput_bytes_per_s=sum(t['payload_bytes'] for t in good)/(makespan/1000)),tasks=tasks)
    with attempt.open('x',encoding='utf-8') as f:
        json.dump(report,f,indent=2)
    if len(good)!=len(items):
        raise RuntimeError('Parallel phase failed; preserve journals and inspect '+str(attempt))
    return [value for value,_ in outputs], report

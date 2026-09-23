import subprocess, sys, time, json, re, os
root = int(sys.argv[1]); out = sys.argv[2]; limit_kb = int(os.environ.get('RSS_KILL_KB', '20971520')); killed = False
peak_tree = (0, 0.0, []); per = {}; timeline = []; t0 = time.time()
def kind(cmd):
    p = re.search(r' -p (\S+)', cmd); pkg = p.group(1) if p else ''
    if 'orchestrion' in cmd and ' toolexec ' in cmd:
        tool = 'compile' if '/compile ' in cmd else ('link' if '/link ' in cmd else 'other')
        return 'orchestrion-toolexec/' + tool, pkg
    if re.search(r'/compile( |$)', cmd): return 'compile', pkg
    if re.search(r'/link( |$)', cmd): return 'link', pkg
    if 'orchestrion' in cmd: return 'orchestrion:' + ' '.join(cmd.split()[1:3])[:40], pkg
    if re.search(r'(^|/)go( |$)', cmd.split(' ')[0] + ' '): return 'go', pkg
    return os.path.basename(cmd.split(' ')[0])[:30], pkg
while True:
    try: os.kill(root, 0)
    except OSError: break
    ps = subprocess.run(['ps', '-axo', 'pid=,ppid=,rss=,command='], capture_output=True, text=True).stdout.splitlines()
    procs = {}
    for l in ps:
        f = l.split(None, 3)
        if len(f) < 4: continue
        procs[int(f[0])] = (int(f[1]), int(f[2]), f[3])
    kids = {}
    for pid, (pp, rss, cmd) in procs.items(): kids.setdefault(pp, []).append(pid)
    tree, stack = [], [root]
    while stack:
        p = stack.pop()
        if p in procs: tree.append(p)
        stack.extend(kids.get(p, []))
    tot = sum(procs[p][1] for p in tree)
    top = sorted(((procs[p][1], kind(procs[p][2])) for p in tree), reverse=True)[:6]
    for rss, k in top:
        key = k[0] + ' ' + k[1]
        per[key] = max(per.get(key, 0), rss)
    el = round(time.time() - t0, 1)
    if tot > peak_tree[0]: peak_tree = (tot, el, top)
    if tot > limit_kb and not killed:
        killed = True
        for p in tree:
            try: os.kill(p, 9)
            except OSError: pass
    timeline.append((el, tot, top[:3]))
    time.sleep(1)
res = {'peak_tree_rss_kb': peak_tree[0], 'peak_tree_at_s': peak_tree[1], 'peak_tree_top': peak_tree[2],
       'top_process_peaks_kb': sorted(per.items(), key=lambda x: -x[1])[:15], 'samples': len(timeline), 'killed_at_limit': killed, 'duration_s': round(time.time()-t0,1)}
json.dump(res, open(out + '.summary.json', 'w'), indent=1)
with open(out + '.timeline.txt', 'w') as f:
    for el, tot, top in timeline: f.write(f"{el}s tree={tot//1024}MB top={[(r//1024, k) for r, k in top]}\n")

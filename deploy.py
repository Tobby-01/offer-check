# Deploy to the Vercel project "offer-check" (production). Token injected by the sandbox proxy.
import os, json, base64, subprocess
ROOT = os.path.dirname(os.path.abspath(__file__))
files = []
for d, dirs, fs in os.walk(ROOT):
    dirs[:] = [x for x in dirs if not x.startswith('.') and x != 'node_modules']
    for f in fs:
        rel = os.path.relpath(os.path.join(d, f), ROOT)
        if rel in ('deploy.py', 'test.js') or f.startswith('.'): continue
        files.append({'file': rel, 'data': base64.b64encode(open(os.path.join(d, f), 'rb').read()).decode(), 'encoding': 'base64'})
body = {'name': 'offer-check', 'project': 'offer-check', 'target': 'production', 'files': files,
        'projectSettings': {'framework': None, 'buildCommand': None, 'outputDirectory': None, 'installCommand': None}}
open('/tmp/oc.json', 'w').write(json.dumps(body))
out = subprocess.run(['curl', '-s', '-X', 'POST', 'https://api.vercel.com/v13/deployments?teamId=team_aj8wcgIz0M9gAnxUxpdHYtvQ&skipAutoDetectionConfirmation=1', '-H', 'Content-Type: application/json', '--data-binary', '@/tmp/oc.json'], capture_output=True, text=True).stdout
r = json.loads(out)
print(json.dumps({k: r.get(k) for k in ('id', 'url', 'readyState', 'alias', 'error')}, indent=1), len(files), 'files')

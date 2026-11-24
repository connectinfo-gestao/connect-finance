import os, secrets, hashlib, time, threading
from flask import Flask, request, jsonify
import psycopg
from psycopg.types.json import Jsonb
from werkzeug.security import check_password_hash, generate_password_hash
app=Flask(__name__)
app.config['MAX_CONTENT_LENGTH']=4*1024*1024
ORIGIN='https://connectinfo-gestao.github.io'
KEYS={'connect-finance-'+x+'-v1' for x in ('local','cards','categories','accounts','transfers','planning')}
EMAIL=os.getenv('FINANCE_EMAIL','').strip().lower()
PASSWORD=os.getenv('FINANCE_PASSWORD','')
HASH=generate_password_hash(PASSWORD) if len(PASSWORD)>=16 else None
attempts=[]; mutex=threading.Lock()
def db(): return psycopg.connect(os.environ['DATABASE_URL'],connect_timeout=8)
def digest(t): return hashlib.sha256(t.encode()).hexdigest()
@app.after_request
def headers(r):
    if request.headers.get('Origin')==ORIGIN:
        r.headers['Access-Control-Allow-Origin']=ORIGIN
        r.headers['Access-Control-Allow-Headers']='Authorization, Content-Type'
        r.headers['Access-Control-Allow-Methods']='GET, PUT, POST, OPTIONS'
    r.headers['X-Content-Type-Options']='nosniff'; r.headers['Cache-Control']='no-store'; r.headers['Vary']='Origin'; return r
@app.get('/')
def index(): return jsonify(app='Connect Finance',version='2.6-homologacao-sync',sync=bool(EMAIL and HASH))
@app.get('/health')
def health():
    try:
        with db() as c: c.execute('SELECT 1')
        return jsonify(database='connected',status='ok')
    except Exception: return jsonify(status='unavailable'),503
def schema(c):
    c.execute('CREATE TABLE IF NOT EXISTS cf_sessions (token text PRIMARY KEY, expires timestamptz NOT NULL)')
    c.execute('CREATE TABLE IF NOT EXISTS cf_state (id integer PRIMARY KEY, revision bigint NOT NULL, data jsonb NOT NULL)')
    c.execute('CREATE TABLE IF NOT EXISTS cf_history (revision bigint PRIMARY KEY, data jsonb NOT NULL, saved timestamptz DEFAULT now())')
def auth(c):
    t=request.headers.get('Authorization','').removeprefix('Bearer ')
    return len(t)==64 and c.execute('SELECT 1 FROM cf_sessions WHERE token=%s AND expires>now()',(digest(t),)).fetchone()
@app.post('/login')
def login():
    if not EMAIL or not HASH: return jsonify(error='Login não configurado'),503
    with mutex:
        now=time.monotonic(); attempts[:]=[x for x in attempts if now-x<60]
        if len(attempts)>=8: return jsonify(error='Aguarde um minuto'),429
        attempts.append(now)
    j=request.get_json(silent=True) or {};
    if not isinstance(j,dict): return jsonify(error='Dados inválidos'),400
    p=j.get('password',''); e=j.get('email','')
    if not isinstance(p,str) or len(p)>256 or not isinstance(e,str) or not check_password_hash(HASH,p) or e.strip().lower()!=EMAIL: return jsonify(error='Credenciais inválidas'),401
    t=secrets.token_hex(32)
    with db() as c:
        schema(c); c.execute('DELETE FROM cf_sessions WHERE expires<=now()'); c.execute("INSERT INTO cf_sessions VALUES (%s,now()+interval '8 hours')",(digest(t),))
    return jsonify(token=t)
@app.post('/logout')
def logout():
    with db() as c:
        if auth(c): c.execute('DELETE FROM cf_sessions WHERE token=%s',(digest(request.headers['Authorization'].removeprefix('Bearer ')),))
    return jsonify(ok=True)
@app.route('/state',methods=['GET','PUT'])
def state():
    with db() as c:
        schema(c)
        if not auth(c): return jsonify(error='Faça login'),401
        if request.method=='GET':
            r=c.execute('SELECT revision,data FROM cf_state WHERE id=1').fetchone(); return jsonify(revision=r[0],data=r[1]) if r else jsonify(revision=0,data=None)
        j=request.get_json(silent=True) or {};
        if not isinstance(j,dict): return jsonify(error='Dados inválidos'),400
        d=j.get('data'); rev=j.get('revision')
        if type(rev)!=int or not isinstance(d,dict) or set(d)!=KEYS or any(not isinstance(v,dict if k.endswith('categories-v1') else list) for k,v in d.items()): return jsonify(error='Dados inválidos'),400
        c.execute('SELECT pg_advisory_xact_lock(2525)'); r=c.execute('SELECT revision,data FROM cf_state WHERE id=1').fetchone(); current=r[0] if r else 0
        if rev!=current: return jsonify(error='Conflito de versões'),409
        if r: c.execute('INSERT INTO cf_history(revision,data) VALUES (%s,%s) ON CONFLICT DO NOTHING',(current,Jsonb(r[1])))
        c.execute('INSERT INTO cf_state VALUES (1,%s,%s) ON CONFLICT(id) DO UPDATE SET revision=excluded.revision,data=excluded.data',(current+1,Jsonb(d)))
        return jsonify(revision=current+1)
@app.errorhandler(Exception)
def error(e):
    from werkzeug.exceptions import HTTPException
    if isinstance(e,HTTPException): return jsonify(error=e.name),e.code
    return jsonify(error='Serviço indisponível'),503
if __name__=='__main__':
    from waitress import serve
    serve(app,host='0.0.0.0',port=int(os.getenv('PORT','10000')))

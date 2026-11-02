/* Reglet core : registre local inaltérable (journal en ajout seul, chaîné SHA-256),
   formulaires déclaratifs, exports, sauvegarde, licence hors ligne.
   Aucune donnée ne quitte l'appareil. */
'use strict';
const R = (() => {
  // ---------------------------------------------------------------- utilitaires
  const $ = (s, el = document) => el.querySelector(s);
  const h = (tag, attrs = {}, ...kids) => {
    const e = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs || {})) {
      if (v == null || v === false) continue;
      if (k.startsWith('on')) e.addEventListener(k.slice(2), v);
      else if (k === 'html') e.innerHTML = v;
      else e.setAttribute(k, v === true ? '' : v);
    }
    for (const k of kids.flat()) if (k != null && k !== false) e.append(k.nodeType ? k : document.createTextNode(k));
    return e;
  };
  const pad = n => String(n).padStart(2, '0');
  const fmtDT = iso => { const d = new Date(iso); return `${pad(d.getDate())}/${pad(d.getMonth() + 1)}/${d.getFullYear()} ${pad(d.getHours())}:${pad(d.getMinutes())}`; };
  const fmtD = iso => { if (!iso) return ''; const d = new Date(iso); return `${pad(d.getDate())}/${pad(d.getMonth() + 1)}/${d.getFullYear()}`; };
  const today = () => new Date().toISOString().slice(0, 10);
  const nowLocal = () => { const d = new Date(); d.setMinutes(d.getMinutes() - d.getTimezoneOffset()); return d.toISOString().slice(0, 16); };
  const b64u = buf => btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  const unb64u = s => Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((s.length + 3) % 4)), c => c.charCodeAt(0));
  // JSON canonique : clés triées, pour que l'empreinte soit stable
  const canon = v => Array.isArray(v) ? '[' + v.map(canon).join(',') + ']'
    : v && typeof v === 'object' ? '{' + Object.keys(v).sort().map(k => JSON.stringify(k) + ':' + canon(v[k])).join(',') + '}'
    : JSON.stringify(v);
  const sha256 = async s => [...new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(s)))]
    .map(b => b.toString(16).padStart(2, '0')).join('');

  // ---------------------------------------------------------------- stockage
  let db, APP;
  const GENESIS = '0'.repeat(64);
  const openDB = name => new Promise((ok, ko) => {
    const rq = indexedDB.open(name, 1);
    rq.onupgradeneeded = () => {
      const d = rq.result;
      d.createObjectStore('journal', { keyPath: 'seq' });
      d.createObjectStore('kv');
    };
    rq.onsuccess = () => ok(rq.result); rq.onerror = () => ko(rq.error);
  });
  const tx = (store, mode, fn) => new Promise((ok, ko) => {
    const t = db.transaction(store, mode); const s = t.objectStore(store);
    const r = fn(s); t.oncomplete = () => ok(r && r.result); t.onerror = () => ko(t.error);
  });
  const all = () => tx('journal', 'readonly', s => s.getAll());
  const kvGet = k => tx('kv', 'readonly', s => s.get(k));
  const kvSet = (k, v) => tx('kv', 'readwrite', s => s.put(v, k));

  let cache = [];
  async function load() { cache = (await all()).sort((a, b) => a.seq - b.seq); return cache; }

  // Ajout d'une écriture : jamais de modification ni de suppression.
  let writing = Promise.resolve();
  function append(type, data, extra = {}) {
    writing = writing.then(async () => {
      const last = cache[cache.length - 1];
      const e = {
        seq: last ? last.seq + 1 : 1,
        ts: new Date().toISOString(),
        type, data,
        author: (await kvGet('operateur')) || '',
        ...extra,
        prev: last ? last.hash : GENESIS,
      };
      e.hash = await sha256(canon({ ...e, hash: undefined }));
      await tx('journal', 'readwrite', s => s.add(e));
      cache.push(e);
      return e;
    });
    return writing;
  }

  async function verify(list = cache) {
    let prev = GENESIS;
    for (const e of list) {
      if (e.prev !== prev) return { ok: false, at: e.seq, why: 'chaînage rompu' };
      const hh = await sha256(canon({ ...e, hash: undefined }));
      if (hh !== e.hash) return { ok: false, at: e.seq, why: 'écriture altérée' };
      prev = e.hash;
    }
    return { ok: true, n: list.length, last: prev };
  }

  // Corrections : une écriture rectificative pointe vers l'originale, qui reste visible.
  const corrections = () => {
    const m = {};
    for (const e of cache) if (e.corrects) (m[e.corrects] = m[e.corrects] || []).push(e);
    return m;
  };
  const effective = e => {
    const c = corrections()[e.seq];
    return c ? { ...e.data, ...c[c.length - 1].data } : e.data;
  };

  // ---------------------------------------------------------------- licence
  // Clé = "<préfixe>-<numéro>-<signature Ed25519 de '<app>|<numéro>'>", vérifiée hors ligne.
  async function licenceOK() {
    const L = await kvGet('licence');
    if (!L || !L.key || !APP.publicKey) return false;
    const m = L.key.trim().match(/^[A-Z]{2}-(\d{6})-([A-Za-z0-9_-]{80,90})$/);
    if (!m) return false;
    try {
      const key = await crypto.subtle.importKey('raw', unb64u(APP.publicKey), { name: 'Ed25519' }, false, ['verify']);
      return await crypto.subtle.verify('Ed25519', key, unb64u(m[2]), new TextEncoder().encode(APP.id + '|' + Number(m[1])));
    } catch (e) { return false; }
  }

  // ---------------------------------------------------------------- formulaires
  function field(f, val) {
    const id = 'f_' + f.k;
    let input;
    const common = { id, name: f.k, required: f.required || null };
    if (f.type === 'select') {
      input = h('select', common, h('option', { value: '' }, '—'),
        ...(typeof f.options === 'function' ? f.options() : f.options).map(o => {
          const [v, l] = Array.isArray(o) ? o : [o, o];
          return h('option', { value: v, selected: String(val) === String(v) }, l);
        }));
    } else if (f.type === 'textarea') {
      input = h('textarea', { ...common, rows: 3 }, val || '');
    } else if (f.type === 'bool') {
      input = h('input', { ...common, type: 'checkbox', checked: !!val, required: null });
      return h('label', { class: 'row check', 'data-k': f.k }, input, h('span', {}, f.label));
    } else if (f.type === 'photo') {
      input = h('input', { ...common, type: 'file', accept: 'image/*', capture: 'environment', required: null });
    } else {
      const t = { number: 'number', date: 'date', datetime: 'datetime-local', time: 'time' }[f.type] || 'text';
      input = h('input', { ...common, type: t, step: f.step || (t === 'number' ? 'any' : null), inputmode: t === 'number' ? 'decimal' : null,
        value: val ?? (f.type === 'datetime' && f.now ? nowLocal() : f.type === 'date' && f.now ? today() : '') });
    }
    return h('label', { class: 'row', 'data-k': f.k },
      h('span', {}, f.label, f.unit ? h('small', {}, ' (' + f.unit + ')') : '', f.required ? h('b', { class: 'req' }, ' *') : ''),
      input, f.help ? h('small', { class: 'help' }, f.help) : '');
  }

  const shrink = file => new Promise(ok => {
    const img = new Image(); const url = URL.createObjectURL(file);
    img.onload = () => {
      const s = Math.min(1, 1200 / Math.max(img.width, img.height));
      const c = document.createElement('canvas'); c.width = img.width * s; c.height = img.height * s;
      c.getContext('2d').drawImage(img, 0, 0, c.width, c.height);
      URL.revokeObjectURL(url); ok(c.toDataURL('image/jpeg', 0.7));
    };
    img.src = url;
  });

  async function readForm(form, T) {
    const d = {};
    for (const f of T.fields) {
      const el = form.elements[f.k]; if (!el) continue;
      if (f.type === 'bool') d[f.k] = el.checked;
      else if (f.type === 'number') d[f.k] = el.value === '' ? null : Number(el.value);
      else if (f.type === 'photo') d[f.k] = el.files[0] ? await shrink(el.files[0]) : null;
      else d[f.k] = el.value.trim();
    }
    return d;
  }

  // ---------------------------------------------------------------- vues
  let view = { tab: null, from: '', to: '', q: '' };
  const main = () => $('#main');

  function nav() {
    const n = $('#nav'); n.innerHTML = '';
    for (const T of APP.types.filter(t => !t.hidden)) {
      n.append(h('button', { class: view.tab === T.id ? 'on' : '', onclick: () => { view.tab = T.id; render(); } }, T.icon ? T.icon + ' ' : '', T.short || T.label));
    }
    n.append(h('button', { class: view.tab === '_reg' ? 'on' : '', onclick: () => { view.tab = '_reg'; render(); } }, '▤ ', APP.registerLabel || 'Registre'));
    n.append(h('button', { class: view.tab === '_set' ? 'on' : '', onclick: () => { view.tab = '_set'; render(); } }, '⚙ Réglages'));
  }

  async function status() {
    const v = await verify();
    const lic = await licenceOK();
    const s = $('#status'); s.innerHTML = '';
    s.append(h('span', { class: v.ok ? 'ok' : 'ko' },
      v.ok ? `✓ Registre intègre · ${v.n} écriture${v.n > 1 ? 's' : ''}` : `✗ Registre altéré à l'écriture n° ${v.at} (${v.why})`));
    if (!lic) s.append(h('span', { class: 'demo' }, `Version d'essai · ${Math.max(0, APP.demoLimit - cache.length)} écritures restantes`));
    const last = await kvGet('lastBackup');
    const days = last ? Math.floor((Date.now() - new Date(last)) / 864e5) : null;
    if (cache.length && (days == null || days >= 7))
      s.append(h('button', { class: 'warn', onclick: backup }, days == null ? '⚠ Aucune sauvegarde : sauvegarder' : `⚠ Dernière sauvegarde il y a ${days} j : sauvegarder`));
  }

  function formView(T, base) {
    const form = h('form', { class: 'card', novalidate: true });
    const corr = base ? effective(base) : {};
    form.append(h('h2', {}, base ? `Rectifier l'écriture n° ${base.seq}` : T.label));
    if (T.intro && !base) form.append(h('p', { class: 'intro' }, T.intro));
    for (const f of T.fields) form.append(field(f, corr[f.k]));
    if (base) form.append(field({ k: '_motif', label: 'Motif de la rectification', required: true }, ''));
    const msg = h('div', { class: 'check' });
    form.append(msg);
    const upd = async () => {
      const d = await readForm(form, { fields: T.fields.filter(f => f.type !== 'photo') });
      for (const f of T.fields) if (f.showIf) form.querySelector(`[data-k="${f.k}"]`).style.display = f.showIf(d) ? '' : 'none';
      const c = T.check ? T.check(d) : T.warn ? T.warn(d) : null;
      msg.className = 'check ' + (c ? (c.ok ? 'ok' : 'ko') : '');
      msg.textContent = c ? c.msg : '';
    };
    form.addEventListener('input', upd); form.addEventListener('change', upd); setTimeout(upd);
    form.append(h('div', { class: 'actions' },
      h('button', { type: 'submit', class: 'primary' }, base ? 'Enregistrer la rectification' : 'Enregistrer'),
      base ? h('button', { type: 'button', onclick: () => render() }, 'Annuler') : ''));
    form.addEventListener('submit', async ev => {
      ev.preventDefault();
      if (!(await licenceOK()) && cache.length >= APP.demoLimit) { alertBox('Version d\'essai terminée : saisissez votre clé dans Réglages.'); return; }
      const d = await readForm(form, T);
      for (const f of T.fields) {
        const visible = !f.showIf || f.showIf(d);
        if (visible && f.required && (d[f.k] === '' || d[f.k] == null)) {
          alertBox('Champ obligatoire : ' + f.label); form.elements[f.k].focus(); return;
        }
        if (!visible) delete d[f.k];
      }
      if (T.validate) { const err = T.validate(d); if (err) { alertBox(err); return; } }
      const c = T.check ? T.check(d) : null;
      if (c && !c.ok && T.needsAction && !d[T.needsAction]) { alertBox('Non conforme : indiquez l\'action corrective.'); return; }
      const extra = { conf: c ? c.ok : null };
      if (T.number) d[T.number] = base ? effective(base)[T.number] : cache.filter(x => x.type === T.id && !x.corrects).length + 1;
      if (base) { extra.corrects = base.seq; extra.motif = form.elements._motif.value.trim(); if (!extra.motif) { alertBox('Indiquez le motif.'); return; } }
      const e = await append(T.id, d, extra);
      toast(`Écriture n° ${e.seq} enregistrée`);
      render();
    });
    return form;
  }

  const alertBox = m => { const d = h('div', { class: 'toast ko' }, m); document.body.append(d); setTimeout(() => d.remove(), 3500); };
  const toast = m => { const d = h('div', { class: 'toast' }, m); document.body.append(d); setTimeout(() => d.remove(), 2200); };

  function filtered(types) {
    const corr = corrections();
    return cache.filter(e => !e.corrects && (!types || types.includes(e.type)))
      .filter(e => (!view.from || e.ts.slice(0, 10) >= view.from) && (!view.to || e.ts.slice(0, 10) <= view.to))
      .filter(e => !view.q || JSON.stringify(effective(e)).toLowerCase().includes(view.q.toLowerCase()))
      .map(e => ({ e, d: effective(e), c: corr[e.seq] || [] }));
  }

  function listView(T) {
    const rows = filtered([T.id]).reverse().slice(0, 50);
    const box = h('div', { class: 'card' }, h('h3', {}, 'Dernières écritures'));
    if (!rows.length) { box.append(h('p', { class: 'muted' }, 'Aucune écriture.')); return box; }
    for (const { e, d, c } of rows) {
      const conf = c.length ? c[c.length - 1].conf : e.conf;
      box.append(h('div', { class: 'item ' + (conf === false ? 'nc' : '') },
        h('div', { class: 'meta' }, `n° ${e.seq} · ${fmtDT(e.ts)}`, e.author ? ` · ${e.author}` : '', c.length ? h('span', { class: 'tag' }, 'rectifiée') : ''),
        h('div', {}, T.summary ? T.summary(d) : Object.values(d).filter(x => typeof x !== 'object').join(' · ')),
        conf === false ? h('div', { class: 'ncmsg' }, T.check ? T.check(d).msg : 'Non conforme') : '',
        h('button', { class: 'link', onclick: () => { main().innerHTML = ''; main().append(formView(T, e)); window.scrollTo(0, 0); } }, 'Rectifier')));
    }
    return box;
  }

  function filters(onchange) {
    return h('div', { class: 'filters no-print' },
      h('label', {}, 'Du ', h('input', { type: 'date', value: view.from, onchange: ev => { view.from = ev.target.value; onchange(); } })),
      h('label', {}, ' au ', h('input', { type: 'date', value: view.to, onchange: ev => { view.to = ev.target.value; onchange(); } })),
      h('input', { type: 'search', placeholder: 'Rechercher…', value: view.q, onchange: ev => { view.q = ev.target.value; onchange(); } }));
  }

  async function registerView() {
    const st = (await kvGet('settings')) || {};
    const v = await verify();
    const wrap = h('div', { class: 'register' });
    wrap.append(filters(() => render()));
    wrap.append(h('div', { class: 'actions no-print' },
      h('button', { class: 'primary', onclick: () => window.print() }, 'Imprimer / PDF'),
      h('button', { onclick: exportCSV }, 'Export tableur (CSV)'),
      h('button', { onclick: backup }, 'Sauvegarde complète')));
    const head = h('div', { class: 'reghead' },
      h('h2', {}, APP.registerTitle || APP.name),
      h('div', {}, APP.settings.filter(s => st[s.k] && s.type !== 'textarea').map(s => h('div', {}, h('b', {}, s.label + ' : '), st[s.k]))),
      h('div', { class: 'small' }, `Édité le ${fmtDT(new Date().toISOString())} · période : ${view.from ? 'du ' + fmtD(view.from) : 'depuis la première écriture'} ${view.to ? 'au ' + fmtD(view.to) : 'jusqu\'à ce jour'}`),
      h('div', { class: 'small' }, v.ok ? `Intégrité vérifiée : ${v.n} écritures chaînées, empreinte finale ${v.last.slice(0, 16)}…` : `ALERTE : altération détectée à l'écriture n° ${v.at}`));
    wrap.append(head);
    const groups = APP.registerGroups || APP.types.map(t => ({ label: t.label, types: [t.id], cols: t.cols }));
    for (const g of groups) {
      const rows = filtered(g.types);
      if (!rows.length && groups.length > 1) continue;
      const T0 = APP.types.find(t => t.id === g.types[0]);
      const cols = g.cols || T0.cols || T0.fields.filter(f => f.type !== 'photo').map(f => [f.label, d => fmtVal(f, d[f.k])]);
      const hasConf = !!T0.check;
      const tbl = h('table', {}, h('thead', {}, h('tr', {}, h('th', {}, 'N°'), h('th', {}, 'Saisi le'), cols.map(c => h('th', {}, c[0])), hasConf ? h('th', {}, 'Conf.') : '', h('th', {}, 'Par'))));
      const tb = h('tbody');
      for (const { e, d, c } of rows) {
        const conf = c.length ? c[c.length - 1].conf : e.conf;
        tb.append(h('tr', { class: conf === false ? 'nc' : '' }, h('td', {}, e.seq), h('td', {}, fmtDT(e.ts)), cols.map(col => h('td', {}, col[1](d, e) ?? '')),
          hasConf ? h('td', {}, conf == null ? '' : conf ? 'C' : 'NC') : '', h('td', {}, e.author || '')));
        for (const r of c) tb.append(h('tr', { class: 'corr' }, h('td', {}, r.seq), h('td', {}, fmtDT(r.ts)),
          h('td', { colspan: cols.length + (hasConf ? 1 : 0) }, `Rectification de l'écriture n° ${e.seq} : ${r.motif || ''}. Valeurs initiales conservées ci-dessus, valeurs rectifiées affichées.`), h('td', {}, r.author || '')));
      }
      wrap.append(h('h3', {}, g.label, h('small', {}, ` · ${rows.length}`)), h('div', { class: 'tw' }, tbl.appendChild(tb) && tbl));
    }
    return wrap;
  }

  const fmtVal = (f, v) => v == null || v === '' ? '' : f.type === 'bool' ? (v ? 'oui' : 'non') : f.type === 'date' ? fmtD(v)
    : f.type === 'datetime' ? fmtDT(v) : f.type === 'select' && Array.isArray((typeof f.options === 'function' ? f.options() : f.options)[0])
      ? ((typeof f.options === 'function' ? f.options() : f.options).find(o => String(o[0]) === String(v)) || [, v])[1] : String(v);

  async function settingsView() {
    const st = (await kvGet('settings')) || {};
    const box = h('div', {});
    const f1 = h('form', { class: 'card' }, h('h2', {}, 'Établissement'),
      ...APP.settings.map(s => field(s, st[s.k])),
      h('div', { class: 'actions' }, h('button', { class: 'primary', type: 'submit' }, 'Enregistrer')));
    f1.addEventListener('submit', async ev => {
      ev.preventDefault(); const n = {};
      for (const s of APP.settings) n[s.k] = f1.elements[s.k].value.trim();
      await kvSet('settings', n); toast('Réglages enregistrés'); APP.onSettings && APP.onSettings(n);
    });
    box.append(f1);
    const op = h('form', { class: 'card' }, h('h2', {}, 'Opérateur sur cet appareil'),
      field({ k: 'op', label: 'Nom ou initiales (inscrit sur chaque écriture)' }, await kvGet('operateur')),
      h('div', { class: 'actions' }, h('button', { class: 'primary', type: 'submit' }, 'Enregistrer')));
    op.addEventListener('submit', async ev => { ev.preventDefault(); await kvSet('operateur', op.elements.op.value.trim()); toast('Opérateur enregistré'); });
    box.append(op);
    if (APP.extraSettings) box.append(await APP.extraSettings());
    const lic = await licenceOK();
    const L = (await kvGet('licence')) || {};
    const lf = h('form', { class: 'card' }, h('h2', {}, 'Licence'),
      h('p', {}, lic ? `Licence n° ${Number(L.key.split('-')[1])} active. Achat unique, aucun abonnement.` : `Version d'essai limitée à ${APP.demoLimit} écritures. Achat unique : ${APP.price}, sans abonnement.`),
      lic ? '' : h('p', {}, h('a', { href: APP.buyUrl, target: '_blank', rel: 'noopener' }, 'Acheter la licence')),
      field({ k: 'key', label: 'Clé de licence', help: 'Reçue par e-mail après l\'achat. Collez-la en entier.' }, L.key),
      h('div', { class: 'actions' }, h('button', { class: 'primary', type: 'submit' }, 'Activer')));
    lf.addEventListener('submit', async ev => {
      ev.preventDefault();
      await kvSet('licence', { key: lf.elements.key.value.replace(/\s+/g, '') });
      toast((await licenceOK()) ? 'Licence activée' : 'Clé non reconnue'); render();
    });
    box.append(lf);
    const bk = h('div', { class: 'card' }, h('h2', {}, 'Sauvegarde et restauration'),
      h('p', {}, 'Les données restent sur cet appareil. Sauvegardez chaque semaine le fichier dans votre Google Drive, Dropbox ou une clé USB : il contient tout le registre et son chaînage.'),
      h('div', { class: 'actions' }, h('button', { class: 'primary', onclick: backup }, 'Télécharger la sauvegarde'),
        h('label', { class: 'btn' }, 'Restaurer un fichier', h('input', { type: 'file', accept: '.json', hidden: true, onchange: restore }))));
    box.append(bk);
    return box;
  }

  async function backup() {
    const payload = { app: APP.id, version: 1, exported: new Date().toISOString(), settings: await kvGet('settings'), journal: cache };
    const v = await verify();
    payload.seal = v.last;
    const blob = new Blob([JSON.stringify(payload)], { type: 'application/json' });
    const a = h('a', { href: URL.createObjectURL(blob), download: `${APP.id}-sauvegarde-${today()}.json` });
    document.body.append(a); a.click(); a.remove();
    await kvSet('lastBackup', new Date().toISOString()); status();
  }

  async function restore(ev) {
    const f = ev.target.files[0]; if (!f) return;
    const p = JSON.parse(await f.text());
    if (p.app !== APP.id) return alertBox('Ce fichier ne vient pas de cette application.');
    const v = await verify(p.journal);
    if (!v.ok) return alertBox(`Sauvegarde altérée (écriture n° ${v.at}) : restauration refusée.`);
    if (cache.length > p.journal.length) return alertBox('Le registre actuel est plus récent que la sauvegarde : restauration refusée.');
    if (cache.length && cache.some((e, i) => !p.journal[i] || p.journal[i].hash !== e.hash))
      return alertBox('La sauvegarde ne prolonge pas le registre actuel : restauration refusée.');
    await tx('journal', 'readwrite', s => { for (const e of p.journal.slice(cache.length)) s.put(e); });
    if (p.settings) await kvSet('settings', p.settings);
    await load(); toast(`${p.journal.length} écritures restaurées`); render();
  }

  function exportCSV() {
    const lines = [];
    for (const T of APP.types) {
      const rows = filtered([T.id]); if (!rows.length) continue;
      const fs = T.fields.filter(f => f.type !== 'photo');
      lines.push([T.label]);
      lines.push(['N°', 'Saisi le', 'Opérateur', ...fs.map(f => f.label), 'Conforme', 'Rectifiée', 'Empreinte']);
      for (const { e, d, c } of rows) lines.push([e.seq, fmtDT(e.ts), e.author, ...fs.map(f => fmtVal(f, d[f.k])),
        e.conf == null ? '' : (c.length ? c[c.length - 1].conf : e.conf) ? 'oui' : 'non', c.length ? 'oui' : '', e.hash]);
      lines.push([]);
    }
    const csv = '﻿' + lines.map(r => r.map(x => `"${String(x ?? '').replace(/"/g, '""')}"`).join(';')).join('\r\n');
    const a = h('a', { href: URL.createObjectURL(new Blob([csv], { type: 'text/csv' })), download: `${APP.id}-${today()}.csv` });
    document.body.append(a); a.click(); a.remove();
  }

  async function render() {
    nav(); await status();
    const m = main(); m.innerHTML = '';
    m.classList.toggle('wide', view.tab === '_reg');
    if (view.tab === '_reg') m.append(await registerView());
    else if (view.tab === '_set') m.append(await settingsView());
    else {
      const T = APP.types.find(t => t.id === view.tab);
      if (T.custom) m.append(await T.custom());
      else m.append(formView(T), listView(T));
    }
  }

  async function start(app) {
    APP = app;
    document.title = app.name;
    db = await openDB(app.id);
    await load();
    if (app.onSettings) app.onSettings((await kvGet('settings')) || {});
    view.tab = app.types[0].id;
    if ('serviceWorker' in navigator && location.protocol.startsWith('http')) navigator.serviceWorker.register('sw.js').catch(() => {});
    if (navigator.storage && navigator.storage.persist) navigator.storage.persist();
    render();
  }

  return { start, append, verify, load, kvGet, kvSet, h, $, fmtD, fmtDT, today, render, toast, alertBox, get cache() { return cache; }, effective, view };
})();

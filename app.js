'use strict';
// Registre des objets mobiliers (« livre de police ») : C. pén. art. 321-7, R321-3 à R321-6-1.
// Tenu par traitement automatisé : intégrité, intangibilité, sécurité ; conservation 10 ans (R321-6-1).
const PIECES = ['Carte nationale d\'identité', 'Passeport', 'Titre de séjour', 'Permis de conduire', 'Autre'];
const physique = d => d.ptype !== 'morale';
const morale = d => d.ptype === 'morale';
const onereux = d => d.op === 'Achat';
const ident = d => physique(d)
  ? [`${(d.nom || '').toUpperCase()} ${d.prenoms || ''}`, d.qualite, d.domicile].filter(Boolean).join(', ')
  : [`${d.denom || ''} (siège : ${d.siege || ''})`, `représentée par ${(d.nom || '').toUpperCase()} ${d.prenoms || ''}, ${d.qualite || ''}`, d.domicile].filter(Boolean).join(', ');

const TYPES = [
  {
    id: 'objet', label: 'Nouvelle entrée au registre', short: 'Entrée', icon: '+', number: 'ordre',
    intro: 'Une ligne par objet, ou par lot d\'objets de moins de 60 € pièce, homogène et acquis auprès d\'une même personne. Le numéro d\'ordre est attribué à l\'enregistrement : reportez-le sur l\'objet.',
    fields: [
      { k: 'date', label: 'Date de l\'opération', type: 'date', required: true, now: true },
      { k: 'op', label: 'Opération', type: 'select', required: true, options: ['Achat', 'Échange', 'Dépôt-vente', 'Acquisition à titre gratuit'] },
      { k: 'ptype', label: 'La contrepartie est', type: 'select', required: true, options: [['physique', 'une personne physique'], ['morale', 'une personne morale (société, association)']] },
      { k: 'denom', label: 'Dénomination', required: true, showIf: morale },
      { k: 'siege', label: 'Siège social', required: true, showIf: morale },
      { k: 'nom', label: 'Nom', required: true },
      { k: 'prenoms', label: 'Prénoms', required: true },
      { k: 'qualite', label: 'Qualité', help: 'Particulier, profession, ou fonction du représentant', required: true },
      { k: 'domicile', label: 'Domicile', type: 'textarea', required: true },
      { k: 'piece', label: 'Pièce d\'identité', type: 'select', required: true, options: PIECES },
      { k: 'pnum', label: 'Numéro de la pièce', required: true },
      { k: 'pdate', label: 'Date de délivrance', type: 'date', required: true },
      { k: 'pauto', label: 'Autorité de délivrance', required: true, help: 'Préfecture, mairie, consulat…' },
      { k: 'nature', label: 'Nature de l\'objet', required: true, help: 'Ex. commode, bague, lot de livres' },
      { k: 'desc', label: 'Description', type: 'textarea', required: true, help: 'Matière, dimensions, et tout signe d\'identification : nom, signature, monogramme, poinçon, numéro de série' },
      { k: 'provenance', label: 'Provenance', help: 'Origine déclarée de l\'objet' },
      { k: 'lot', label: 'Lot regroupé (objets de moins de 60 € pièce)', type: 'bool' },
      { k: 'nb', label: 'Nombre d\'objets du lot', type: 'number', showIf: d => d.lot },
      { k: 'prix', label: 'Prix d\'achat', type: 'number', unit: '€', required: true, showIf: onereux },
      { k: 'valeur', label: 'Valeur vénale estimée', type: 'number', unit: '€', required: true, showIf: d => d.op && !onereux(d) },
      { k: 'reglement', label: 'Mode de règlement', type: 'select', required: true, showIf: onereux, options: ['Virement', 'Chèque', 'Carte bancaire', 'Espèces', 'Autre'] },
      { k: 'patrimoine', label: 'Mesure de protection au titre du code du patrimoine, si connue', help: 'Ex. objet classé monument historique' },
    ],
    validate: d => {
      if (d.pdate && d.pdate > R.today()) return 'La date de délivrance de la pièce est dans le futur.';
      if (d.lot && d.nb && (d.prix || d.valeur) / d.nb > 60) return 'Lot regroupé : la valeur unitaire dépasse 60 €. Enregistrez ces objets séparément.';
      return null;
    },
    warn: d => {
      const w = [];
      if (onereux(d) && d.reglement === 'Espèces' && d.prix > 1000) w.push('paiement en espèces au-dessus de 1 000 € : vérifiez le plafond légal');
      if (onereux(d) && d.reglement === 'Espèces' && /\b(or|argent|platine|bijou|bague|collier|alliance|bracelet|montre)/i.test(`${d.nature} ${d.desc}`))
        w.push('achat de métaux à un particulier : règlement par chèque ou virement uniquement (CMF L112-6), vérifiez');
      return w.length ? { ok: false, msg: 'Attention : ' + w.join(' ; ') } : null;
    },
    summary: d => `n° d'ordre ${d.ordre ?? '?'} · ${d.nature} · ${ident(d).split(',')[0]} · ${d.prix ?? d.valeur ?? ''} €`,
    cols: [
      ['N° d\'ordre', d => d.ordre], ['Date', d => R.fmtD(d.date)],
      ['Objet : nature, description, provenance', d => [d.nature, d.lot ? `Lot de ${d.nb || '?'} objets` : '', d.desc, d.provenance ? 'Provenance : ' + d.provenance : ''].filter(Boolean).join('. ')],
      ['Opération', d => d.op],
      ['Vendeur, apporteur ou déposant : identité, qualité, domicile', ident],
      ['Pièce d\'identité', d => `${d.piece} n° ${d.pnum}`], ['Délivrée le, par', d => `${R.fmtD(d.pdate)}, ${d.pauto}`],
      ['Prix ou valeur (€) et règlement', d => d.prix != null ? `${d.prix} · ${d.reglement}` : `valeur estimée ${d.valeur}`],
      ['Protection patrimoine', d => d.patrimoine],
    ],
  },
];

R.start({
  id: 'reglet-police', name: 'Reglet Livre de police', registerTitle: 'Registre des objets mobiliers (art. 321-7 et R321-3 et suivants du code pénal)',
  registerLabel: 'Registre', registerGroups: [{ label: 'Objets acquis', types: ['objet'] }], types: TYPES, demoLimit: 25, price: '49 € TTC', buyUrl: 'https://payhip.com/b/qkMGE',
  publicKey: 'ac0tXLjtqH1cqcCNliweBFikVKUlNzyK0raG5lNviH4',
  settings: [
    { k: 'nom', label: 'Nom commercial' }, { k: 'exploitant', label: 'Exploitant ou dirigeant' },
    { k: 'adresse', label: 'Adresse de l\'établissement' }, { k: 'siret', label: 'SIRET' },
    { k: 'recepisse', label: 'Récépissé de déclaration en préfecture (n° et date)' },
  ],
});

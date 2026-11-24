const crypto = require('crypto');
const RECEIPT_TYPES = new Set(['image/png', 'image/jpeg', 'image/webp', 'image/gif', 'application/pdf']);
const MAX_RECEIPT_BYTES = 8 * 1024 * 1024;
const MAX_USER_RECEIPT_BYTES = 100 * 1024 * 1024;
const validDate = value => typeof value === 'string' && /^\d{4}-\d{2}-\d{2}$/.test(value) &&
  Number.isFinite(Date.parse(value)) && new Date(value).toISOString().slice(0, 10) === value;
function receiptBytes(r) {
  if (!r || typeof r !== 'object' || typeof r.data !== 'string' || typeof r.mime !== 'string' || !RECEIPT_TYPES.has(r.mime)) return -1;
  const prefix = `data:${r.mime};base64,`;
  if (!r.data.startsWith(prefix) || r.data.length > MAX_RECEIPT_BYTES * 4 / 3 + 100) return -1;
  const encoded = r.data.slice(prefix.length);
  if (!encoded || encoded.length % 4 || !/^[A-Za-z0-9+/]*={0,2}$/.test(encoded)) return -1;
  const bytes = Buffer.from(encoded, 'base64');
  if (bytes.toString('base64') !== encoded || bytes.length > MAX_RECEIPT_BYTES) return -1;
  const signature = r.mime === 'application/pdf' ? bytes.subarray(0,5).toString() === '%PDF-' :
    r.mime === 'image/png' ? bytes.subarray(0,8).equals(Buffer.from([137,80,78,71,13,10,26,10])) :
    r.mime === 'image/jpeg' ? bytes[0] === 255 && bytes[1] === 216 && bytes[2] === 255 :
    r.mime === 'image/gif' ? /^GIF8[79]a$/.test(bytes.subarray(0,6).toString()) :
    bytes.subarray(0,4).toString() === 'RIFF' && bytes.subarray(8,12).toString() === 'WEBP';
  return signature ? bytes.length : -1;
}
function structuralError(obj, depth = 0) {
  if (depth > 12) return 'Record nesting is too deep.';
  if (typeof obj === 'string') return obj.length > 12 * 1024 * 1024 ? 'Field is too long.' : null;
  if (typeof obj === 'number') return Number.isFinite(obj) ? null : 'Invalid number.';
  if (!obj || typeof obj !== 'object') return null;
  if (Array.isArray(obj) && obj.length > 1000) return 'Too many items.';
  for (const [k,v] of Object.entries(obj)) {
    if (['__proto__','constructor','prototype'].includes(k)) return 'Invalid field.';
    if ((k==='id'||k.endsWith('_id')) && v!=null && v!=='' && (typeof v!=='string'||!/^[A-Za-z0-9_-]{1,100}$/.test(v))) return 'Invalid record identifier.';
    const error = structuralError(v, depth + 1); if (error) return error;
  }
  return null;
}
function validateLine(obj, store) {
  const strings = ['id','report_id','line_date','description','supplier_id','category_id','vat_rate_id','postcode_from','postcode_to','vehicle_type','vehicle_reg','mileage_rate_id','purchase_for_dept_id','purchase_for_loc_id','created_at'];
  const numbers = ['amount','vat_amount','distance_miles','rate_up','rate_over','rate_adv','miles_under','miles_over'];
  const allowed = new Set([...strings,...numbers,'line_type','company_car','return_journey','receipts']);
  if (Object.keys(obj).some(k=>!allowed.has(k))) return 'Unknown expense line field.';
  if (!['expense','mileage'].includes(obj.line_type)) return 'Invalid expense line type.';
  for (const k of strings) if (obj[k] != null && (typeof obj[k] !== 'string' || obj[k].length > (k==='description'?4000:200))) return `Invalid ${k}.`;
  for (const k of numbers) if (obj[k] !== undefined && (typeof obj[k] !== 'number' || !Number.isFinite(obj[k]) || Math.abs(obj[k]) > (k.includes('miles')?100000:1000000))) return `Invalid ${k}.`;
  if (typeof obj.amount !== 'number' || !Number.isFinite(obj.amount)) return 'Amount is required.';
  // Signed amounts support explicit refunds; VAT must have the same sign and fit within gross.
  if (obj.vat_amount != null && (Math.abs(obj.vat_amount)>Math.abs(obj.amount)+0.001 || obj.vat_amount*obj.amount<0)) return 'VAT must have the same sign as gross and cannot exceed it.';
  for (const k of ['company_car','return_journey']) if (obj[k] !== undefined && typeof obj[k] !== 'boolean') return `Invalid ${k}.`;
  if (!validDate(obj.line_date)) return 'Use a valid YYYY-MM-DD expense date.';
  if (obj.distance_miles != null && obj.distance_miles < 0) return 'Mileage cannot be negative.';
  for (const [k,s] of Object.entries({supplier_id:'suppliers',category_id:'categories',vat_rate_id:'vat_rates',mileage_rate_id:'mileage_rates',purchase_for_dept_id:'departments',purchase_for_loc_id:'locations'})) {
    if (obj[k] && !store.get(s,obj[k])) return `Unknown ${k}.`;
  }
  // The mileage form stores the vehicle type by name (as mileage rates do), so accept a name or an id.
  if (obj.vehicle_type && !store.get('vehicle_types',obj.vehicle_type) &&
      !store.getAll('vehicle_types').some(v=>v.name===obj.vehicle_type)) return 'Unknown vehicle_type.';
  if (obj.receipts !== undefined && (!Array.isArray(obj.receipts) || obj.receipts.length>20 || obj.receipts.some(r=>receiptBytes(r)<0))) return 'Receipts must be PNG, JPEG, GIF, WebP or PDF files up to 8 MB each.';
  return null;
}
function directoryUser(viewer, u) {
  if (!u) return u;
  const {password_hash,session_version,...safe} = u;
  return viewer.roles?.includes('finance') || viewer.id===u.id ? safe : {id:u.id,full_name:u.full_name,active:u.active,...([u.approver1_id,u.approver2_id].includes(viewer.id)?{approver1_id:u.approver1_id,approver2_id:u.approver2_id}:{})};
}
function fingerprint(u) { return crypto.createHash('sha256').update(JSON.stringify([u.microsoft_oid,u.roles,u.active,u.session_version||0])).digest('hex'); }
function rateLimit({limit, windowMs}) {
  const clients=new Map();
  return (req,res,next)=>{
    const now=Date.now(),key=req.ip;
    if(clients.size>10000) for(const [k,v] of clients) if(v.until<=now) clients.delete(k);
    let bucket=clients.get(key);
    if(!bucket || bucket.until<=now){if(clients.size>=10000&&!bucket)return res.status(429).json({error:'Please try again later.'});bucket={count:0,until:now+windowMs};clients.set(key,bucket);}
    if(++bucket.count>limit){res.set('Retry-After',String(Math.ceil((bucket.until-now)/1000)));return res.status(429).json({error:'Too many requests. Please try again shortly.'});}next();
  };
}
function auditChanges(before,after) {
  const result={};
  for(const k of ['amount','vat_amount','distance_miles','line_date','description','supplier_id','category_id','mileage_rate_id','name','title','notes','status']) {
    if(JSON.stringify(before?.[k])!==JSON.stringify(after?.[k]))result[k]={before:before?.[k]??null,after:after?.[k]??null};
  }
  if(JSON.stringify(before?.receipts)!==JSON.stringify(after?.receipts))result.receipts={before:before?.receipts?.length||0,after:after?.receipts?.length||0};
  return result;
}
function reconciliationError(value) {
  if(value==null)return null;
  if(typeof value!=='object'||Array.isArray(value))return 'Invalid reconciliation.';
  if(value.txs!==undefined && (!Array.isArray(value.txs)||value.txs.length>1000))return 'Invalid statement transactions.';
  for(const tx of value.txs||[]) {
    if(!tx||typeof tx!=='object'||typeof tx.id!=='string'||!/^[A-Za-z0-9_-]{1,100}$/.test(tx.id)||!validDate(tx.date)||typeof tx.description!=='string'||tx.description.length>4000||typeof tx.amount!=='number'||!Number.isFinite(tx.amount)||Math.abs(tx.amount)>1000000)return 'Invalid statement transaction.';
  }
  if(value.tickedLineIds!==undefined && (!Array.isArray(value.tickedLineIds)||value.tickedLineIds.some(id=>typeof id!=='string'||!/^[A-Za-z0-9_-]{1,100}$/.test(id))))return 'Invalid reconciled line identifiers.';
  if(value.fileName!==undefined && (typeof value.fileName!=='string'||value.fileName.length>200))return 'Invalid statement filename.';
  return null;
}
module.exports={receiptBytes,validateLine,structuralError,directoryUser,fingerprint,rateLimit,auditChanges,reconciliationError,MAX_USER_RECEIPT_BYTES};

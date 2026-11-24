const KNOWN_STORES = new Set(['users','categories','departments','locations','vehicle_types',
  'mileage_rates','advisory_rates','mileage_adjustments','suppliers','vat_rates',
  'reports','lines','payment_runs','settings','audit_log']);
const PROTECTED = ['submitted_at','manager_approved_by','manager_approved_at','finance_approved_by',
  'finance_approved_at','reimbursed_at','payment_run_id','rejected_by','rejected_at','rejection_note'];
const finance = u => u.roles?.includes('finance');
const draft = r => ['unsubmitted','rejected'].includes(r.status);
const locked = r => r.status === 'reimbursed' || (r.type === 'creditcard' && r.status === 'approved');
const canEdit = (u,r) => !locked(r) && draft(r) && (finance(u) || r.user_id === u.id);
const canReconcile = (u,r) => !locked(r) && r.type === 'creditcard' && (finance(u) || r.user_id === u.id);
const safeId = id => typeof id === 'string' && /^[A-Za-z0-9_-]{1,100}$/.test(id);

function reportUpdate(existing, input, user, store) {
  const fail = error => ({error});
  const now = new Date().toISOString();
  const reconciliationError=require('./hardening').reconciliationError(input.reconciliation);
  if(reconciliationError)return fail(reconciliationError);
  for(const key of ['title','notes','reference']) if(input[key]!==undefined && (typeof input[key]!=='string'||input[key].length>4000)) return fail('Invalid report text.');
  if (!existing) {
    if ((input.status || 'unsubmitted') !== 'unsubmitted' || PROTECTED.some(k => input[k] != null))
      return fail('New reports must start as unsubmitted.');
    if (!['expense','creditcard'].includes(input.type)) return fail('Invalid report type.');
    if (!finance(user) && !user.roles?.includes(input.type === 'creditcard' ? 'credit_card' : 'employee'))
      return fail('Your permissions do not allow this report type.');
    return {record:{...input,status:'unsubmitted',created_at:now,...Object.fromEntries(PROTECTED.map(k=>[k,null]))}};
  }
  const next = input.status || existing.status;
  const owner = existing.user_id === user.id;
  const account = store.get('users', existing.user_id);
  const manager = !owner && (finance(user) || account?.approver1_id === user.id);
  const second = !owner && finance(user) && existing.manager_approved_by !== user.id;
  const result = {...existing};
  // Lifecycle values are checked against current stored state, then stamped by the server.
  if (next === existing.status) {
    if (PROTECTED.some(k => (input[k] ?? null) !== (existing[k] ?? null)))
      return fail('Approval and payment fields cannot be edited directly.');
    const changed = ['title','notes','reconciliation'].filter(k=>JSON.stringify(input[k])!==JSON.stringify(existing[k]));
    if (!canEdit(user,existing) && !(changed.every(k=>k==='reconciliation') && canReconcile(user,existing)))
      return fail('This report is read-only at its current stage.');
  } else if (draft(existing) && next === (account?.approver1_id ? 'awaiting_manager' : 'awaiting_finance') && (owner || finance(user))) {
    if (!store.getAll('lines').some(l=>l.report_id===existing.id)) return fail('Add at least one line before submitting.');
    for (const k of PROTECTED) result[k] = null;
    result.submitted_at = now;
  } else if (existing.status === 'awaiting_manager' && next === 'awaiting_finance' && manager) {
    result.manager_approved_by = user.id; result.manager_approved_at = now;
  } else if (existing.status === 'awaiting_finance' && next === (existing.type === 'creditcard' ? 'approved' : 'awaiting_reimbursement') && second) {
    result.finance_approved_by = user.id; result.finance_approved_at = now;
  } else if (next === 'rejected' && ((existing.status === 'awaiting_manager' && manager) || (existing.status === 'awaiting_finance' && second) || (existing.status === 'awaiting_reimbursement' && finance(user)))) {
    if (typeof input.rejection_note!=='string'||!input.rejection_note.trim()||input.rejection_note.length>4000) return fail('A reason of up to 4000 characters is required when returning a report.');
    result.rejected_by = user.id; result.rejected_at = now; result.rejection_note = String(input.rejection_note).trim();
  } else if (existing.type === 'expense' && existing.status === 'awaiting_reimbursement' && next === 'reimbursed' && finance(user)) {
    if (input.payment_run_id) {
      const run=store.get('payment_runs',input.payment_run_id);
      if (!run?.report_ids?.includes(existing.id)) return fail('Invalid payment run.');
    }
    result.reimbursed_at = now; result.payment_run_id = input.payment_run_id || null;
  } else return fail('You cannot perform this approval or status change.');
  // Reviewers may change status only; owners/finance may edit allowed content.
  if (canEdit(user,existing)) for(const k of ['title','notes','reconciliation']) {
    if (input[k] === undefined) delete result[k]; else result[k]=input[k];
  }
  else if (canReconcile(user,existing)) {
    if (input.reconciliation === undefined) delete result.reconciliation;
    else result.reconciliation=input.reconciliation;
  }
  result.status=next;
  return {record:result};
}
function receiptValid(receipt) { return require('./hardening').receiptBytes(receipt)>=0; }
module.exports={KNOWN_STORES,canEdit,reportUpdate,receiptValid,safeId};

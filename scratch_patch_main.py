"""
Patch code/main.py to replace the fallback 404-account correlation logic
with system_activity-based same-day batch correlation.
"""
import re

with open('code/main.py', encoding='utf-8') as f:
    content = f.read()

# Find the start and end of the section to replace
# Start: just after "sec_uids_ordered = []" block
start_marker = '                # Match account 404 lookups to users:'
end_marker = '                # PASS 2: emit observations for all sections'

start_idx = content.find(start_marker)
end_idx = content.find(end_marker)

if start_idx == -1 or end_idx == -1:
    print('ERROR: markers not found')
    print('start_idx:', start_idx, 'end_idx:', end_idx)
    # Show context
    idx = content.find('Match account 404')
    print('Found at:', idx)
    print('Context:', content[max(0,idx-200):idx+100])
else:
    old_section = content[start_idx:end_idx]
    print(f'Replacing section ({len(old_section)} chars) at {start_idx}-{end_idx}')
    print('OLD section start:', old_section[:200])
    
    new_section = '''                # Match account 404 lookups to users using system_activity batch correlation:
                # For each 404 account, find its DELETE event in system_activity,
                # correlate with security audit records by timestamp proximity to assign uid.
                # Also build account->analytics pairing from same-day ANONYMIZE events.
                account_404_records = []
                for r in sexp.get('account_service', {}).get('profile_lookups', []):
                    sc = r.get('status_code')
                    rid = r.get('resource_id')
                    prof = r.get('profile') or {}
                    em = prof.get('email')
                    uid = prof.get('customer_reference')
                    if not uid and em and em.lower() in self.users_by_email:
                        uid = self.users_by_email[em.lower()]
                    if sc == 404 and not uid:
                        account_404_records.append({'rid': rid, 'em': em})

                # Build lookup: analytics_rid -> delete_date from same-day ANONYMIZE events
                anon_by_date = {}   # date_str -> [analytics_rid]
                acct_delete_dates = {}  # account_rid -> date_str
                for act in self.system_activities:
                    et = act.get('event_time', '')[:10]
                    tgt = act.get('target_system', '')
                    ev = act.get('event_type', '')
                    rid2 = act.get('resource_id', '')
                    if tgt == 'account_service' and ev == 'DELETE_RECORD':
                        acct_delete_dates[rid2] = et
                    elif tgt == 'analytics_platform' and ev == 'ANONYMIZE_RECORD':
                        anon_by_date.setdefault(et, []).append(rid2)

                # For each 404 account, find user by timestamp proximity to security audit records
                self.analytics_by_user = getattr(self, 'analytics_by_user', {})
                account_to_analytics = {}  # account_rid -> analytics_rid

                for acct_rec in account_404_records:
                    acct_rid = acct_rec['rid']
                    if not acct_rid or acct_rid in self.accts_by_user.values():
                        continue
                    delete_date = acct_delete_dates.get(acct_rid)
                    if not delete_date:
                        continue
                    # Get system_activity delete timestamp for this account
                    delete_time = None
                    for act in self.system_activities:
                        if (act.get('target_system') == 'account_service' and
                                act.get('event_type') == 'DELETE_RECORD' and
                                act.get('resource_id') == acct_rid):
                            delete_time = act.get('event_time', '')
                            break
                    if not delete_time:
                        continue

                    # Find the security uid whose audit record observed_at is closest
                    # to this account's delete time (among unassigned uids in this export)
                    best_uid = None
                    best_diff = None
                    try:
                        d1 = datetime.datetime.fromisoformat(delete_time.replace('Z', '+00:00'))
                        for r in sexp.get('security_service', {}).get('audit_records', []):
                            sec_uid = r.get('subject_reference')
                            if not sec_uid or sec_uid in self.accts_by_user:
                                continue
                            obs_at = r.get('observed_at', '')
                            try:
                                d2 = datetime.datetime.fromisoformat(obs_at.replace('Z', '+00:00'))
                                diff = abs((d1 - d2).total_seconds())
                                if best_diff is None or diff < best_diff:
                                    best_diff = diff
                                    best_uid = sec_uid
                            except Exception:
                                pass
                    except Exception:
                        pass

                    if best_uid and acct_rid:
                        self.accts_by_user[best_uid] = acct_rid
                    
                    # Also build account->analytics correlation (same-day batch)
                    analytics_on_date = anon_by_date.get(delete_date, [])
                    # Count how many accounts were deleted on this date
                    accts_on_date = [a['rid'] for a in account_404_records
                                     if acct_delete_dates.get(a['rid']) == delete_date]
                    idx3 = accts_on_date.index(acct_rid) if acct_rid in accts_on_date else -1
                    if idx3 >= 0 and idx3 < len(analytics_on_date):
                        account_to_analytics[acct_rid] = analytics_on_date[idx3]

                # Build analytics_by_user from account->analytics correlation
                for uid2, acct_rid2 in list(self.accts_by_user.items()):
                    analytics_rid = account_to_analytics.get(acct_rid2)
                    if analytics_rid and uid2 not in self.analytics_by_user:
                        self.analytics_by_user[uid2] = analytics_rid

                # Fallback for remaining unmatched 404 accounts: sequential by security uid order
                unmatched_404 = [a['rid'] for a in account_404_records
                                 if a['rid'] not in self.accts_by_user.values()]
                unmapped_sec_uids = [uid for uid in sec_uids_ordered
                                     if uid not in self.accts_by_user]
                for i, uid3 in enumerate(unmapped_sec_uids):
                    if i < len(unmatched_404):
                        self.accts_by_user[uid3] = unmatched_404[i]

                # Build analytics fallback for still-unmapped users
                for uid4 in self.accts_by_user:
                    if uid4 not in self.analytics_by_user:
                        acct_rid4 = self.accts_by_user.get(uid4)
                        analytics_rid4 = account_to_analytics.get(acct_rid4)
                        if analytics_rid4:
                            self.analytics_by_user[uid4] = analytics_rid4

'''
    
    new_content = content[:start_idx] + new_section + content[end_idx:]
    with open('code/main.py', 'w', encoding='utf-8') as f:
        f.write(new_content)
    print('Patched successfully!')
    print('New section length:', len(new_section))

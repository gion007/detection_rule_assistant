// ─────────────────────────────────────────────────────────────────────────────
// Rule Name    : Unified Brute-Force Authentication Detection
// Description  : Detects brute-force login attempts across five authentication
//                sources by identifying ≥ 5 failed authentication events from
//                the same source IP within a 10-minute window.
//                An optional second stage flags accounts where a SUCCESS follows
//                the burst of failures (potential credential compromise).
// Datasets     : microsoft_windows_raw  – Windows Security event log (4625, 4771, 4776, 4624)
//                msft_azure_ad_raw      – Microsoft Entra ID sign-in logs
//                cisco_ise_raw          – Cisco ISE RADIUS/TACACS auth logs
//                duo_duo_raw            – Duo Security MFA authentication log
//                linux_linux_raw        – Linux auth.log / secure (SSH/PAM)
// MITRE ATT&CK : T1110 – Brute Force
//                  T1110.001 – Password Guessing
//                  T1110.003 – Password Spraying
// Severity     : HIGH
// Author       : detection_rule_assistant
// ─────────────────────────────────────────────────────────────────────────────
//
// XDM field mapping used across all datasets
// ┌─────────────────────────────────┬──────────────────────────────────────────────────────────────────┐
// │ XDM Field                       │ Populated by dataset                                             │
// ├─────────────────────────────────┼──────────────────────────────────────────────────────────────────┤
// │ xdm.event.outcome               │ ALL – OUTCOME_FAILED / OUTCOME_SUCCESS                           │
// │ xdm.source.user.username        │ ALL – normalised login name                                       │
// │ xdm.source.user.upn             │ msft_azure_ad_raw, duo_duo_raw                                   │
// │ xdm.source.ipv4                 │ ALL (where available)                                            │
// │ xdm.source.ipv6                 │ msft_azure_ad_raw, microsoft_windows_raw, cisco_ise_raw          │
// │ xdm.source.host.hostname        │ microsoft_windows_raw, linux_linux_raw                           │
// │ xdm.source.host.ipv4_addresses  │ msft_azure_ad_raw (array field)                                  │
// │ xdm.target.host.hostname        │ linux_linux_raw, microsoft_windows_raw                           │
// │ xdm.event.outcome_reason        │ ALL – human-readable failure reason                              │
// │ xdm.event.original_event_type   │ ALL – e.g. "4625", "CISE_Failed_Attempts", "Failed Password…"   │
// │ xdm.logon.type                  │ microsoft_windows_raw, msft_azure_ad_raw, duo_duo_raw            │
// │ xdm.source.location.country     │ msft_azure_ad_raw, duo_duo_raw                                   │
// │ xdm.source.location.city        │ msft_azure_ad_raw, duo_duo_raw                                   │
// │ xdm.auth.mfa.method             │ duo_duo_raw, msft_azure_ad_raw                                   │
// │ xdm.observer.name               │ cisco_ise_raw, duo_duo_raw                                       │
// └─────────────────────────────────┴──────────────────────────────────────────────────────────────────┘
//
// ─────────────────────────────────────────────────────────────────────────────

config case_sensitive = false timeframe = 1h

// ─── Stage 1: Collect authentication FAILURE events across all sources ───────

datamodel dataset in (
    microsoft_windows_raw,
    msft_azure_ad_raw,
    cisco_ise_raw,
    duo_duo_raw,
    linux_linux_raw
)
// Retain only explicit authentication failure outcomes
| filter xdm.event.outcome = XDM_CONST.OUTCOME_FAILED

// Drop machine / computer accounts (end with $) and anonymous / blank users
| filter xdm.source.user.username != null
    and xdm.source.user.username !~= "^[\-\s\$]+$"
    and xdm.source.user.username !~= "\$$"

// At least one network indicator must be present for brute-force relevance
| filter xdm.source.ipv4 != null
    or xdm.source.ipv6 != null
    or array_length(xdm.source.host.ipv4_addresses) > 0

// ─── Stage 2: Normalise fields across heterogeneous datasets ─────────────────

| alter
    // Unified source IP – prefer dedicated field, fall back to address arrays
    src_ip          = coalesce(
                          xdm.source.ipv4,
                          xdm.source.ipv6,
                          arrayindex(xdm.source.host.ipv4_addresses, 0)
                      ),
    // Normalised username – lowercase UPN if plain username absent
    username        = lowercase(
                          coalesce(
                              xdm.source.user.username,
                              xdm.source.user.upn
                          )
                      ),
    // Best-effort target / victim host
    target_host     = coalesce(
                          xdm.target.host.hostname,
                          xdm.source.host.hostname
                      ),
    datasource      = _dataset,
    fail_reason     = xdm.event.outcome_reason,
    orig_evt_type   = xdm.event.original_event_type,
    country         = xdm.source.location.country,
    city            = xdm.source.location.city,
    logon_type      = xdm.logon.type,
    mfa_method      = xdm.auth.mfa.method

// ─── Stage 3: Bucket into 10-minute windows and aggregate ────────────────────

| bin _time span = 10m

| comp
    count()                     as failure_count,
    values(datasource)          as sources,
    min(_time)                  as window_start,
    max(_time)                  as window_end,
    values(target_host)         as targeted_hosts,
    values(fail_reason)         as failure_reasons,
    values(orig_evt_type)       as event_types,
    values(country)             as src_countries,
    values(city)                as src_cities,
    values(logon_type)          as logon_types,
    values(mfa_method)          as mfa_methods
    by src_ip, username, _time

// ─── Stage 4: Apply brute-force threshold (≥ 5 failures in any 10-min window) ─

| filter failure_count >= 5

// ─── Stage 5: Enrich with derived context fields ─────────────────────────────

| alter
    attack_duration_sec = timestamp_diff(window_end, window_start, "SECOND"),
    num_targeted_hosts  = array_length(targeted_hosts),
    num_sources         = array_length(sources),
    is_multi_source     = if(array_length(sources) > 1, true, false),
    is_multi_host       = if(array_length(targeted_hosts) > 1, true, false),
    // Classify spray vs. stuffing hint (single user = stuffing; multi-host single user = spray)
    attack_pattern      = if(
                              array_length(targeted_hosts) > 1,
                              "password_spray_candidate",
                              "credential_stuffing_candidate"
                          )

| sort desc failure_count

| fields
    window_start,
    window_end,
    attack_duration_sec,
    src_ip,
    username,
    failure_count,
    attack_pattern,
    targeted_hosts,
    num_targeted_hosts,
    is_multi_host,
    sources,
    num_sources,
    is_multi_source,
    failure_reasons,
    event_types,
    src_countries,
    src_cities,
    logon_types,
    mfa_methods


// ─────────────────────────────────────────────────────────────────────────────
// Optional Stage 6: Detect successful login AFTER a brute-force burst
//                   (indicates likely credential compromise).
// To activate: pipe the output above into a join with the success query below,
// or run this as a separate hunt.
// ─────────────────────────────────────────────────────────────────────────────
//
// datamodel dataset in (
//     microsoft_windows_raw,
//     msft_azure_ad_raw,
//     cisco_ise_raw,
//     duo_duo_raw,
//     linux_linux_raw
// )
// | filter xdm.event.outcome = XDM_CONST.OUTCOME_SUCCESS
//     and xdm.source.user.username != null
// | alter
//     src_ip   = coalesce(xdm.source.ipv4, xdm.source.ipv6, arrayindex(xdm.source.host.ipv4_addresses, 0)),
//     username = lowercase(coalesce(xdm.source.user.username, xdm.source.user.upn))
// | join type = inner (
//     < brute_force_results_from_stages_1_to_5 >
//   ) src_ip = src_ip and username = username
// | filter _time > window_end
// | fields _time as success_time, src_ip, username, window_start, window_end,
//          failure_count, sources as brute_force_sources

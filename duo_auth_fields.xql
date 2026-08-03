// ─────────────────────────────────────────────────────────────────────────────
// Query        : Duo Security – Authentication Event Field Exploration
// Dataset      : duo_duo_raw
// Description  : Extracts all authentication-relevant XDM fields from Duo
//                authentication events into a single comp aggregation.
//                Use this to enumerate field values before building detections.
// Filter       : eventtype = "authentication" (excludes administrator/telephony)
// ─────────────────────────────────────────────────────────────────────────────

datamodel dataset = duo_duo_raw
| filter xdm.event.type = "authentication"
| alter
    src_user_groups  = arrayindex(xdm.source.user.groups, 0),
    risk_event_types = arrayindex(xdm.alert.risks, 0)
| comp
    count()                                    as event_count,
    values(xdm.source.user.username)           as src_usernames,
    values(xdm.source.user.upn)                as src_upns,
    values(xdm.source.user.identifier)         as src_user_ids,
    values(xdm.source.user.sam_account_name)   as src_aliases,
    values(src_user_groups)                    as src_user_groups,
    values(xdm.source.user.first_name)         as first_names,
    values(xdm.source.user.last_name)          as last_names,
    values(xdm.source.ipv4)                    as src_ipv4,
    values(xdm.source.ipv6)                    as src_ipv6,
    values(xdm.source.host.hostname)           as src_hostnames,
    values(xdm.source.host.device_id)          as src_device_ids,
    values(xdm.source.host.device_category)    as src_os_category,
    values(xdm.source.location.country)        as src_countries,
    values(xdm.source.location.city)           as src_cities,
    values(xdm.source.location.region)         as src_regions,
    values(xdm.event.outcome)                  as outcomes,
    values(xdm.event.outcome_reason)           as outcome_reasons,
    values(xdm.event.id)                       as event_ids,
    values(xdm.event.operation)                as operations,
    values(xdm.event.operation_sub_type)       as mfa_factors,
    values(xdm.logon.type)                     as logon_types,
    values(xdm.auth.mfa.method)                as mfa_methods,
    values(risk_event_types)                   as risk_event_types,
    values(xdm.target.resource.name)           as target_app_names,
    values(xdm.target.resource.id)             as target_app_keys,
    values(xdm.intermediate.ipv4)              as auth_device_ipv4,
    values(xdm.intermediate.ipv6)              as auth_device_ipv6,
    values(xdm.intermediate.host.hostname)     as auth_device_names,
    values(xdm.intermediate.location.country)  as auth_device_countries,
    values(xdm.intermediate.location.city)     as auth_device_cities,
    values(xdm.intermediate.location.region)   as auth_device_regions,
    values(xdm.observer.action)                as result_raw
  by _vendor, _product

twaf_reqstat:reqstat_log_handler(twaf:ctx().events.stat, twaf:ctx().policy_uuid)
twaf:run(twaf)
collectgarbage("collect")

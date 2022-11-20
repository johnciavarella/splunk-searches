# Find which data should go in which datamodel
## This search will run very slow

code(index=*
| fields index, tag, user, action, object_category
| eval datamodel = if(tag="alert", index."."."alert", datamodel)
| eval datamodel = if(tag="listening" AND tag="port", index."."."application_state_deprecated"."."."endpoint", datamodel)
| eval datamodel = if(tag="process" AND tag="report", index."."."application_state_deprecated"."."."endpoint", datamodel)
| eval datamodel = if(tag="service" AND tag="report", index."."."application_state_deprecated"."."."endpoint", datamodel)
| eval datamodel = if(tag="authentication" AND action!="success" AND user!="*$", index."."."authentication", datamodel)
| eval datamodel = if(tag="certificate", index."."."certificates", datamodel)
| eval datamodel = if(tag="change" AND NOT (object_category=file OR object_category=directory OR object_category=registry), index."."."change"."."."change_analysis_deprecated", datamodel)
| eval datamodel = if(tag="dlp" AND tag="incident", index."."."data_loss_prevention", datamodel)
| eval datamodel = if(tag="database", index."."."database", datamodel)
| eval datamodel = if(tag="email", index."."."email", datamodel)
| eval datamodel = if(tag="endpoint" AND tag="filesystem", index."."."endpoint", datamodel)
| eval datamodel = if(tag="endpoint" AND tag="registry", index."."."endpoint", datamodel)
| eval datamodel = if(tag="track_event_signatures" AND (signature="*" OR signature_id="*"), index."."."event_signatures", datamodel)
| eval datamodel = if(tag="messaging", index."."."interprocess_messaging", datamodel)
| eval datamodel = if(tag="ids" AND tag="attack", index."."."intrusion_detection", datamodel)
| eval datamodel = if(tag="inventory" AND (tag="cpu" OR tag="memory" OR tag="network" OR tag="storage" OR (tag="system" AND tag="version") OR tag="user" OR tag="virtual"), index."."."inventory", datamodel)
| eval datamodel = if(tag="jvm", index."."."jvm", datamodel)
| eval datamodel = if(tag="malware" AND tag="attack", index."."."malware", datamodel)
| eval datamodel = if(tag="network" AND tag="resolution" AND tag="dns", index."."."network_resolution_dns", datamodel)
| eval datamodel = if(tag="network" AND tag="session", index."."."network_sessions", datamodel)
| eval datamodel = if(tag="network" AND tag="communicate", index."."."network_traffic", datamodel)
| eval datamodel = if(tag="performance" AND (tag="cpu" OR tag="facilities" OR tag="memory" OR tag="storage" OR tag="network" OR (tag="os" AND ((tag="time" AND tag="synchronize") OR tag="uptime"))), index."."."performance", datamodel)
| eval datamodel = if(tag="ticketing", index."."."ticket_managment", datamodel)
| eval datamodel = if(tag="update" AND tag="status", index."."."updates", datamodel)
| eval datamodel = if(tag="vulnerability" AND tag="report", index."."."vulnerabilities", datamodel)
| eval datamodel = if(tag="web", index."."."web", datamodel)
| rex field=datamodel "(?<index>[^\\.]+)\.(?<datamodel>.*)"
| makemv delim="." datamodel
| stats values(index) as index by datamodel)
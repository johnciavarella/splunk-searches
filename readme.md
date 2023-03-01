# Navigate 

[Admin](#1-admin)

[Getting insights into data](#2-getting-insights)

[Misc](#3-misc)

<h1 id="1-admin">Admin Searches</h1>

## What indexes are used in saved searches

```
| rest splunk_server=* /servicesNS/-/-/configs/conf-savedsearches | rename eai:appName as app eai:acl.sharing as sharing | eval status = if(disabled=0, "Enabled" , "Disabled") | foreach cron_schedule action.email.to action.email.subject [eval <<FIELD>> = if(len('<<FIELD>>') > 0,'<<FIELD>>', "-")] | fields app title author search cron_schedule action.email action.email.subject action.email.to splunk_server sharing status | join app type=left [| rest splunk_server=local /servicesNS/-/-/apps/local | rename title as app label as app_label | table app app_label] | search status=enabled cron_schedule!="-" | where cron_schedule!="-" | eventstats dc(title) as concurrentCron by cron_schedule | table app app_label title author sharing cron_schedule concurrentCron search | sort -concurrentCron cron_schedule app title
| search search=*index*
| fields app search
| rex field=search max_match=100 "index(?:\s=\s|=\s|\s=|=)(?<index>.*?)(?:\s|$|\)|\'|\,)"
| eval index_count=mvcount(index)
| eval index=mvdedup(index)
| fields app index_count index search
```

## Searches per index by time searches
Get ths list of which indexes are getting searches by Number of searches, Oldest Events searched, Average, and Median. Useful for indexing strategy 

```
index="_audit"  OR field=TERM(info=completed) NOT typeahead | rex "search_id='(?<search_id>.*?)'"  | eval search_et=if(search_et="N/A",0,search_et)  | rex "', search='(?<thesearch>.*)"| rex max_match=100 field=thesearch "index(?:\s=\s|=\s|\s=|=)(?<index>.*?)(?:\s|$|\)|\'|\,)" | eval lookback=_time-search_et  | fields search_id lookback index
| eval index=replace(index,"\"","")
| eval lookback=round(lookback/60/60/24,0)
| where lookback<1800
| stats dc(search_id) AS numOfSearches max(lookback) as oldest_event_searched_Days avg(lookback) as Average_Lookback_Days median(lookback) as Median_Lookback_Days by index
|  sort - numOfSearches
| search index!=_*
```

## Time delay by index
```
index=*
| eval indexed_time=strftime(_indextime,"%+")
| eval time=strftime(_time,"%+")
| eval delayEPOCH=_time-_indextime
| eval delay=tostring(_time-_indextime, "duration")

| table delay indexed_time time _raw
```

## All scheduled searches

```
| rest /services/saved/searches splunk_server=* | search is_scheduled=1 | dedup title | table title search description eai:acl:owner
```

## What Datamodels exist (with acceleration)

```
| rest /services/data/models| table acceleration eai:appName title | rename eai:appName as App title as datamodel | eval acceleration=if(acceleration == 1, "True", "False”)
```

## All Time Searches

```
index=_audit action="search" search="*" apiEndTime=*ZERO_TIME* | table user, apiStartTime, apiEndTime  savedsearch_name search
```

## Size of buckets on indexers
Can be useful to see how much will archive off
```
| dbinspect  index=* | eval Size_GB=sizeOnDiskMB/1024
| table index state Size_GB endEpoch startEpoch
```

<h1 id="2-getting-insights">Getting insights into data</h1>

## Find which data should go in which datamodel
 This search will run very slow and is a VERY expensive search.

```
index=*
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
| stats values(index) as index by datamodel
```

<h1 id="3-misc">Misc</h1>

## Datamodel to Index/Sourcetype mapping

```
| tstats values(sourcetype) as sourcetype WHERE index=* by index
| mvexpand sourcetype
| join sourcetype [
| datamodel
| rex field=_raw "\"modelName\"\s*\:\s*\"(?<modelName>[^\"]+)\""
| search NOT modelName IN (Splunk_CIM_Validation)
| fields modelName
| table modelName
| map maxsearches=60 search="tstats summariesonly=true count from datamodel=$modelName$ by sourcetype | eval modelName=\"$modelName$\"" ] | fields modelName index sourcetype
| mvcombine sourcetype
```

## Datamodel Audit credit [Hurricane Labs](https://hurricanelabs.com/splunk-tutorials/how-to-improve-your-data-model-acceleration-in-splunk/)

```
| rest /servicesNS/-/-/admin/macros splunk_server=local 
| search title=Cim_*_indexes 
| table title definition 
| rex field=title "cim_(?<datamodel>\w+)_indexes" 
| rename title AS macro 
| join type=outer datamodel 
    [| rest /servicesNS/nobody/-/datamodel/model splunk_server=local 
    | table title acceleration 
    | rex field=acceleration "\"enabled\":(?<acceleration_enabled>[^,\"]+)" 
    | rex field=acceleration "\"earliest_time\":\"(?<acceleration_earliest>[^\"]+)" 
    | fillnull acceleration_earliest value="N/A" 
    | rename title AS datamodel 
    | fields - acceleration] 
| join type=outer datamodel 
    [| `datamodel("Splunk_Audit", "Datamodel_Acceleration")` 
    | `drop_dm_object_name("Datamodel_Acceleration")` 
    | eval "size(MB)"=round(size/1048576,1), "retention(days)"=if(retention==0,"unlimited",round(retention/86400,1)), "complete(%)"=round(complete*100,1), "runDuration(s)"=round(runDuration,1) 
    | sort 100 + datamodel 
    | table datamodel,complete(%),size(MB),access_time 
    | eval datamodel=if(datamodel="Endpoint.Filesystem","Endpoint",datamodel)] 
| join type=outer datamodel 
    [| rest splunk_server=local /servicesNS/-/-/configs/conf-savedsearches 
    | search action.correlationsearch.label=* 
    | rename action.correlationsearch.label AS rule_name 
    | fields + title,rule_name,dispatch.earliest_time,dispatch.latest_time 
    | join type=outer title 
        [| rest splunk_server=local /servicesNS/-/-/configs/conf-savedsearches 
        | fields + title,search,disabled] 
    | rex max_match=0 field=search "datamodel\W{1,2}(?<datamodel>\w+)" 
    | rex max_match=0 field=search "tstats.*?from datamodel=(?<datamodel>\w+)" 
    | eval datamodel2=case(match(search, "src_dest_tstats"), mvappend("Network_Traffic", "Intrusion_Detection", "Web"), match(search, "(access_tracker|inactive_account_usage)"), "Authentication", match(search, "malware_operations_tracker"), "Malware", match(search, "(primary_functions|listeningports|localprocesses|services)_tracker"), "Application_State", match(search, "useraccounts_tracker"), "Compute_Inventory") 
    | eval datamodel=mvappend(datamodel, datamodel2) 
    | search datamodel=* 
    | mvexpand datamodel 
    | eval uses_tstats=if(match(search, ".*tstats.*"), "yes", "no") 
    | eval enabled=if(disabled==0, "Yes", "No") 
    | search enabled=yes 
    | stats count(rule_name) as correlation_searches_enabled by datamodel 
    | fillnull correlation_searches_enabled value="0"] 
| fieldformat access_time=strftime(access_time, "%m/%d/%Y %H:%M:%S") 
| table datamodel acceleration_enabled, acceleration_earliest, macro, definition, complete(%), size(MB), correlation_searches_enabled, access_time 
| sort -acceleration_enabled definition -complete(%) size(MB)
```

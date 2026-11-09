from __future__ import annotations
import base64
import json
from pathlib import Path
from swarmpot.funnel import build_funnel, observation_evidence
from swarmpot.util import write_json, append_jsonl


def test_observations_exclude_prompts_and_commands(tmp_path):
    path=tmp_path/'agent'/'realtime_context.txt'
    path.parent.mkdir()
    path.write_text('[00:00:01] USER: /maintenance\n'
                    '[00:00:02] EXECUTING: curl /maintenance\n'
                    '[00:00:03] COMMAND RESULT: Exit code 0\n'
                    'STDOUT: server response\n/maintenance\n'
                    '[00:00:04] EXECUTING: echo /maintenance\n')
    evidence=observation_evidence(tmp_path,['/maintenance'])
    assert len(evidence)==1
    assert evidence[0]['line']==5


def test_tcp_http_on_ssh_and_auth_only_are_not_entry(tmp_path):
    for event in ({'eventid':'cowrie.session.connect','session':'a'},
                  {'eventid':'cowrie.client.version','session':'a','version':'HEAD /login HTTP/1.1'},
                  {'eventid':'cowrie.login.success','session':'b'}):
        append_jsonl(tmp_path/'cowrie/cowrie.json',event)
    result=build_funnel(tmp_path)
    assert result['strict_ssh_entry'] is False
    assert result['authenticated_sessions']==1
    assert len(result['protocol_confusion_events'])==1
    assert result['first_executed_command'] is None


def test_authenticated_audited_backend_command_is_entry(tmp_path):
    for event in ({'eventid':'cowrie.session.connect','session':'s'},
                  {'eventid':'cowrie.client.version','session':'s','version':'SSH-2.0-OpenSSH'},
                  {'eventid':'cowrie.client.kex','session':'s'},
                  {'eventid':'cowrie.login.success','session':'s'},
                  {'eventid':'cowrie.proxy.backend_connected','session':'s','local_port':1234}):
        append_jsonl(tmp_path/'cowrie/cowrie.json',event)
    log=tmp_path/'decoy_log/commands.tsv'
    log.parent.mkdir()
    log.write_text('2026-11-09T00:00:00Z\tport-1234\t'+base64.b64encode(b'id').decode()+'\n')
    result=build_funnel(tmp_path)
    assert result['strict_ssh_entry'] is True
    assert result['command_sessions']==1
    assert result['first_executed_command']['input']=='id'
    assert result['protocol_confusion_events']==[]


def test_unauthenticated_unmatched_command_not_entry(tmp_path):
    log=tmp_path/'decoy_log/commands.tsv'
    log.parent.mkdir()
    log.write_text('2026-11-09T00:00:00Z\tport-1234\t'+base64.b64encode(b'id').decode()+'\n')
    assert build_funnel(tmp_path)['strict_ssh_entry'] is False


def test_retention_requires_entry_and_source_clock():
    from swarmpot.metrics import validated_retention
    actions=[{'tool_started_at':'2026-11-09T00:00:00+00:00'},
             {'tool_started_at':'2026-11-09T00:00:01+00:00'},
             {'tool_started_at':'2026-11-09T00:00:02+00:00'}]
    funnel={'first_executed_command':{'timestamp':'2026-11-09T00:00:01.200Z'}}
    assert validated_retention(actions,{})[0]==[]
    assert validated_retention(actions,funnel)[0]==[actions[2]]
    assert validated_retention([{}],funnel)[1]=='source_tool_times_unavailable'


def test_new_episode_does_not_reuse_generated_state(tmp_path):
    from swarmpot.breadcrumbs import write_prepared, Gateway, MINIMAL
    from dataclasses import asdict
    config=tmp_path/'config.json'
    write_json(config, {'version':MINIMAL,'gateway':asdict(Gateway(authentication='password')),'reference_date':'2026-11-09'})
    old=tmp_path/'old'/'breadcrumb_profile.json'
    new=tmp_path/'new'/'breadcrumb_profile.json'
    write_prepared(config,old,True,'http://unused')
    record=json.loads(old.read_text());record['reset_canary']='PRIVATE_OLD_LURE_STATE';write_json(old,record)
    write_prepared(config,new,True,'http://unused')
    assert 'PRIVATE_OLD_LURE_STATE' not in new.read_text()
    assert 'PRIVATE_OLD_LURE_STATE' in old.read_text()  # archival logs retained


def test_cowrie_command_request_requires_backend_audit(tmp_path):
    for event in ({'eventid':'cowrie.session.connect','session':'s'},
                  {'eventid':'cowrie.login.success','session':'s'},
                  {'eventid':'cowrie.command.input','session':'s','input':'id'}):
        append_jsonl(tmp_path/'cowrie/cowrie.json',event)
    assert build_funnel(tmp_path)['strict_ssh_entry'] is False

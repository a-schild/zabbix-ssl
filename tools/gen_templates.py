#!/usr/bin/env python3
"""Generate Zabbix 7.0 templates for zabbix-ssl from a compact service model.

Mirrors the conventions already used in Template_App_HTTPS_Autodiscovery.xml:
  * combined SHA1/MD5 weak-signature trigger (find ... like)
  * ranged certificate-expiry windows (expired / <7d / <Nd / <Md)
  * a "no data" trigger on the lifetime item
  * a per-service certificate-lifetime graph
"""
import os
import uuid
import yaml

# Repository root (this script lives in <repo>/tools/).
REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DESC = "https://github.com/a-schild/zabbix-ssl/"
GROUPS = [
    {"uuid": "f3d62922ddb94a4a838b318d3f662fa5", "name": "Active Hosts"},
    {"uuid": "7df96b18c230490a9a0a9e2307226338", "name": "Templates"},
]


def u():
    return uuid.uuid4().hex


def sslkey(port, method, check):
    return f"ssltls.check[{{HOST.CONN}}:{port},{method},{check}]"


def ref(tname, key):
    return f"/{tname}/{key}"


def trig(expr, name, priority):
    return {"uuid": u(), "expression": expr, "name": name, "priority": priority}


def make_item(name, itype, key, value_type=None, units=None, delay="1h",
              history="90d", trends=None, status=None, valuemap=None,
              preprocessing=None, description=None, app=None, triggers=None):
    it = {"uuid": u(), "name": name, "type": itype, "key": key,
          "delay": delay, "history": history}
    if value_type:
        it["value_type"] = value_type
    if units:
        it["units"] = units
    if trends is not None:
        it["trends"] = trends
    if status:
        it["status"] = status
    if valuemap:
        it["valuemap"] = {"name": valuemap}
    if description:
        it["description"] = description
    if preprocessing:
        it["preprocessing"] = preprocessing
    if app:
        it["tags"] = [{"tag": "Application", "value": app}]
    if triggers:
        it["triggers"] = triggers
    return it


def build_template(svc):
    tname = svc["tname"]
    app = svc["app"]
    label = svc["label"]
    port = svc["port"]
    method = svc["method"]

    k_digest = sslkey(port, method, "digestmode")
    k_end = sslkey(port, method, "enddate")
    k_life = sslkey(port, method, "lifetime")
    k_simple = sslkey(port, method, "simple")
    k_ssl3 = sslkey(port, method, "ssl3")
    k_start = sslkey(port, method, "startdate")

    r_life = ref(tname, k_life)
    r_simple = ref(tname, k_simple)
    r_digest = ref(tname, k_digest)
    r_ssl3 = ref(tname, k_ssl3)
    r_run = ref(tname, svc["run_key"])

    def bool2dec():
        return [{"type": "BOOL_TO_DECIMAL", "parameters": [""]}]

    # --- triggers -----------------------------------------------------------
    t_down = trig(f"max({r_run},#3)=0",
                  f"{label} service is down on {{HOST.NAME}}", "AVERAGE")
    t_notrun = trig(f"last({r_simple})=0",
                    f"{label} SSL not running on {{HOST.NAME}}", "HIGH")
    t_weak = trig(
        f'find({r_digest},,"like","sha1")=1 or find({r_digest},,"like","md5")=1',
        f"{label} uses weak certificate signature (SHA1/MD5) on {{HOST.NAME}}",
        "AVERAGE")
    t_ssl3 = trig(f"last({r_ssl3})=1",
                  f"{label} ssl3 poodle vulnerable on {{HOST.NAME}}", "WARNING")

    life_trigs = [trig(f"last({r_life})<0",
                       f"{label} certificate on {{HOST.NAME}} expired", "DISASTER")]
    prev = 0
    prios = ["HIGH", "AVERAGE", "WARNING"]
    for (sec, lbl), prio in zip(svc["warn"], prios):
        life_trigs.append(trig(
            f"last({r_life})<{sec} and last({r_life})>{prev}",
            f"{label} certificate on {{HOST.NAME}} expires in less than {lbl}",
            prio))
        prev = sec
    life_trigs.append(trig(f"nodata({r_life},2h)=1",
                           f"{label} certificate check returned no data on {{HOST.NAME}}",
                           "INFO"))

    # --- items --------------------------------------------------------------
    items = []
    if svc.get("perf_key"):
        items.append(make_item(f"{label} service performance", "SIMPLE",
                               svc["perf_key"], value_type="FLOAT", units="s",
                               delay="1m", history="1w", trends="365d", app=app))
    items.append(make_item(svc["run_name"], svc["run_type"], svc["run_key"],
                           value_type="UNSIGNED", delay="1m", history="1w",
                           trends="365d", valuemap="Service state",
                           description=svc.get("run_desc"), app=app,
                           triggers=[t_down]))
    items.append(make_item(f"SSL {label} certificate digest mode", "EXTERNAL",
                           k_digest, value_type="CHAR", trends="0", app=app,
                           triggers=[t_weak]))
    items.append(make_item(f"SSL {label} certificate end date", "EXTERNAL",
                           k_end, value_type="CHAR", trends="0", app=app))
    items.append(make_item(f"SSL {label} certificate time until expire", "EXTERNAL",
                           k_life, value_type="FLOAT", units="s", trends="365d",
                           app=app, triggers=life_trigs))
    items.append(make_item(f"SSL {label} certificate running", "EXTERNAL",
                           k_simple, value_type="UNSIGNED", trends="365d",
                           valuemap="Service state", preprocessing=bool2dec(),
                           app=app, triggers=[t_notrun]))
    items.append(make_item(f"SSL {label} sslv3 poodle vulnerable", "EXTERNAL",
                           k_ssl3, value_type="UNSIGNED", trends="365d",
                           status="DISABLED", preprocessing=bool2dec(), app=app,
                           triggers=[t_ssl3]))
    items.append(make_item(f"SSL {label} certificate start date", "EXTERNAL",
                           k_start, value_type="CHAR", trends="0", app=app))

    # Regular graphs are a top-level zabbix_export element in the 7.0 schema
    # (graph_items reference items by host+key), NOT a per-template key.
    graph = {"uuid": u(), "name": f"{label} certificate time until expire",
             "graph_items": [{"color": "1A7C11",
                              "item": {"host": tname, "key": k_life}}]}

    template = {
        "uuid": u(),
        "template": tname,
        "name": tname,
        "description": DESC,
        "groups": [{"name": "Active Hosts"}, {"name": "Templates"}],
        "items": items,
        "valuemaps": [{
            "uuid": u(), "name": "Service state",
            "mappings": [{"value": "0", "newvalue": "Down"},
                         {"value": "1", "newvalue": "Up"}],
        }],
    }
    return template, graph


def dump(path, built):
    """built: list of (template, graph) tuples from build_template()."""
    templates = [t for t, _ in built]
    graphs = [g for _, g in built]
    export = {
        "version": "7.0",
        "template_groups": GROUPS,
        "templates": templates,
        "graphs": graphs,
    }
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        yaml.dump({"zabbix_export": export}, f, sort_keys=False,
                  allow_unicode=True, default_flow_style=False, width=100000)
    print("wrote", path)


W_7_15_29 = [(604800, "7 days"), (1296000, "15 days"), (2505600, "29 days")]
W_7_45_90 = [(604800, "7 days"), (3888000, "45 days"), (7776000, "90 days")]

# --- HTTPS ------------------------------------------------------------------
https = build_template({
    "tname": "Template App HTTPS Service", "label": "HTTPS", "app": "HTTPS service",
    "port": "443", "method": "native",
    "run_name": "HTTPS service is running", "run_type": "SIMPLE",
    "run_key": "net.tcp.service[tcp,,443]",
    "run_desc": "Not https since we have a problem with libcurl in debian8 and Zabbix using TLS 1.0",
    "warn": W_7_15_29,
})
dump(f"{REPO}/Template_App_HTTPS_Service.xml", [https])

# --- FTP --------------------------------------------------------------------
ftp = build_template({
    "tname": "Template App FTP Service", "label": "FTP", "app": "FTP service",
    "port": "21", "method": "ftp",
    "run_name": "FTP service is running", "run_type": "ZABBIX_ACTIVE",
    "run_key": "net.tcp.listen[21]",
    "warn": W_7_15_29,
})
dump(f"{REPO}/Template_App_FTP_Service.xml", [ftp])

# --- POP / IMAP / SMTP (6 templates) ---------------------------------------
mail = [
    {"tname": "Template App IMAP Service", "label": "IMAP", "app": "IMAP service",
     "port": "143", "method": "imap", "run_name": "IMAP service is running",
     "run_type": "SIMPLE", "run_key": "net.tcp.service[imap]",
     "perf_key": "net.tcp.service.perf[imap]", "warn": W_7_45_90},
    {"tname": "Template App IMAPS Service", "label": "IMAPS", "app": "IMAPS service",
     "port": "993", "method": "native", "run_name": "IMAPS service is running",
     "run_type": "SIMPLE", "run_key": "net.tcp.service[tcp,,993]",
     "perf_key": "net.tcp.service.perf[tcp,,993]", "warn": W_7_15_29},
    {"tname": "Template App POP3 Service", "label": "POP3", "app": "POP3 service",
     "port": "110", "method": "pop3", "run_name": "POP3 service is running",
     "run_type": "SIMPLE", "run_key": "net.tcp.service[pop]",
     "perf_key": "net.tcp.service.perf[pop]", "warn": W_7_45_90},
    {"tname": "Template App POP3S Service", "label": "POP3S", "app": "POP3S service",
     "port": "995", "method": "native", "run_name": "POP3S service is running",
     "run_type": "SIMPLE", "run_key": "net.tcp.service[tcp,,995]",
     "perf_key": "net.tcp.service.perf[tcp,,995]", "warn": W_7_15_29},
    {"tname": "Template App SMTP Service", "label": "SMTP", "app": "SMTP service",
     "port": "25", "method": "smtp", "run_name": "SMTP service is running",
     "run_type": "SIMPLE", "run_key": "net.tcp.service[smtp]",
     "perf_key": "net.tcp.service.perf[smtp]", "warn": W_7_45_90},
    {"tname": "Template App SMTPS Service", "label": "SMTPS", "app": "SMTPS service",
     "port": "465", "method": "native", "run_name": "SMTPS service is running",
     "run_type": "SIMPLE", "run_key": "net.tcp.service[tcp,,465]",
     "perf_key": "net.tcp.service.perf[tcp,,465]", "warn": W_7_15_29},
]
dump(f"{REPO}/Template_App_SSL_POP_IMAP_SMTP.xml", [build_template(s) for s in mail])

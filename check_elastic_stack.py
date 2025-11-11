#!/usr/bin/env python3
# check_elastic_stack.py
# piccolo script per fare check base su elasticsearch / kibana / logstash

import argparse
import sys
import requests
from requests.auth import HTTPBasicAuth

requests.packages.urllib3.disable_warnings()

def main():
    parser = argparse.ArgumentParser(description="Check Elastic Stack stile Nagios")
    parser.add_argument("--check", required=True, help="elasticsearch | kibana | logstash")
    parser.add_argument("--host", required=True, help="es: https://localhost:9200")
    parser.add_argument("--user", default=None)
    parser.add_argument("--password", default=None)
    parser.add_argument("--timeout", type=int, default=5)
    parser.add_argument("--insecure", action="store_true", help="salta verifica certificato tls")

    args = parser.parse_args()

    try:
        if args.check == "elasticsearch":
            check_elasticsearch(args)
        elif args.check == "kibana":
            check_kibana(args)
        elif args.check == "logstash":
            check_logstash(args)
        else:
            print("UNKNOWN - parametro --check non valido")
            sys.exit(3)
    except Exception as e:
        print(f"UNKNOWN - errore generico: {e}")
        sys.exit(3)

def do_request(url, args):
    try:
        resp = requests.get(
            url,
            auth=HTTPBasicAuth(args.user, args.password) if args.user else None,
            timeout=args.timeout,
            verify=not args.insecure
        )
        return resp
    except requests.exceptions.RequestException as e:
        print(f"UNKNOWN - errore connessione: {e}")
        sys.exit(3)

def check_elasticsearch(args):
    url = args.host.rstrip("/") + "/_cluster/health"
    r = do_request(url, args)

    if r.status_code != 200:
        print(f"CRITICAL - Elasticsearch HTTP {r.status_code}")
        sys.exit(2)

    data = r.json()
    status = data.get("status")
    nodes = data.get("number_of_nodes", "?")

    if status == "green":
        print(f"OK - Cluster verde, nodi={nodes}")
        sys.exit(0)
    elif status == "yellow":
        print(f"WARNING - Cluster giallo, nodi={nodes}")
        sys.exit(1)
    elif status == "red":
        print(f"CRITICAL - Cluster rosso, nodi={nodes}")
        sys.exit(2)
    else:
        print(f"UNKNOWN - stato={status}")
        sys.exit(3)

def check_kibana(args):
    url = args.host.rstrip("/") + "/api/status"
    r = do_request(url, args)

    if r.status_code != 200:
        print(f"CRITICAL - Kibana HTTP {r.status_code}")
        sys.exit(2)

    try:
        data = r.json()
    except Exception:
        print("UNKNOWN - risposta non json")
        sys.exit(3)

    overall = data.get("status", {}).get("overall", {})
    level = overall.get("level", "unknown")

    if level == "available":
        print("OK - Kibana disponibile")
        sys.exit(0)
    elif level == "degraded":
        print("WARNING - Kibana degradato")
        sys.exit(1)
    elif level == "unavailable":
        print("CRITICAL - Kibana non disponibile")
        sys.exit(2)
    else:
        print(f"UNKNOWN - stato {level}")
        sys.exit(3)

def check_logstash(args):
    url = args.host.rstrip("/") + "/_node"
    r = do_request(url, args)

    if r.status_code != 200:
        print(f"CRITICAL - Logstash HTTP {r.status_code}")
        sys.exit(2)

    data = r.json()
    name = data.get("name")
    pipelines = data.get("pipelines", {})

    if name:
        if len(pipelines) == 0:
            print(f"WARNING - Logstash ok ({name}) ma nessuna pipeline")
            sys.exit(1)
        else:
            print(f"OK - Logstash attivo ({name}), pipelines={len(pipelines)}")
            sys.exit(0)
    else:
        print("UNKNOWN - campo name mancante")
        sys.exit(3)


if __name__ == "__main__":
    main()

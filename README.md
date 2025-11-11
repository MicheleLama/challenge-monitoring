# challenge monitoring elastic stack

script in python3 per fare i check base su elasticsearch, kibana e logstash.
output in formato nagios (0 ok, 1 warning, 2 critical, 3 unknown).

### uso

```bash
python3 check_elastic_stack.py --check elasticsearch --host https://localhost:9200 --user elastic --password changeme --insecure
```
